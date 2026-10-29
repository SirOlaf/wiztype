from iced_x86 import (
    Decoder,
    FlowControl,
    Instruction,
    InstructionInfoFactory,
    Mnemonic,
    OpAccess,
    OpKind,
    Register,
    RegisterExt,
)
from memobj import WindowsProcess

from .memory import CoreObjectFactoryNode, CoreType
from .type_tree import read_map_nodes

# mov rax, [rip+factory]; mov ebx, edx; movzx edx, r8b; mov r9, [rax+8]
# this is the start of CoreObjectFactory::CreateCoreObject
CORE_OBJECT_FACTORY_PATTERN = rb"\x48\x8B\x05....\x8B\xDA\x41\x0F\xB6\xD0\x4C\x8B\x48\x08"

# registers that do not survive a call
_VOLATILE_REGISTERS = {
    Register.RAX,
    Register.RCX,
    Register.RDX,
    Register.R8,
    Register.R9,
    Register.R10,
    Register.R11,
}

_WRITE_ACCESSES = {
    OpAccess.WRITE,
    OpAccess.COND_WRITE,
    OpAccess.READ_WRITE,
    OpAccess.READ_COND_WRITE,
}

_INFO_FACTORY = InstructionInfoFactory()


def _read_rip_global(process: WindowsProcess, pattern: bytes) -> int:
    """read the global loaded by the rip relative mov at the start of pattern"""
    mov_addr = process.scan_one(pattern, module="WizardGraphicalClient.exe")

    # 48 8B 05 [33 16 E3 01]
    offset = process.read_formatted(mov_addr + 3, "i")

    # 7 is the length of the mov instruction
    return process.read_formatted(mov_addr + offset + 7, "Q")


def _decode(process: WindowsProcess, address: int, size: int = 0x400):
    """yield instructions starting at address until the first ret"""
    decoder = Decoder(64, process.read_memory(address, size), ip=address)

    for instruction in decoder:
        yield instruction

        if instruction.flow_control == FlowControl.RETURN:
            return


def _follow_jumps(process: WindowsProcess, address: int) -> int:
    """follow jmp thunks to the real function"""
    while True:
        instruction = next(_decode(process, address, 16))

        if instruction.mnemonic == Mnemonic.JMP and instruction.op0_kind == OpKind.NEAR_BRANCH64:
            address = instruction.near_branch_target
        else:
            return address


def _is_direct_call(instruction: Instruction) -> bool:
    return instruction.mnemonic == Mnemonic.CALL and instruction.op0_kind == OpKind.NEAR_BRANCH64


def _find_vtable(
        process: WindowsProcess,
        function: int,
        this_registers: set[Register],
        *,
        skip_first_call: bool = False,
        depth: int = 2,
) -> int | None:
    """
    find the last vtable written to `this` by a create function or constructor

    base constructors are followed so that vtable stores done in them count too,
    the last store is the most derived vtable
    """
    vtable = None
    lea_targets: dict[Register, int] = {}
    this_registers = set(this_registers)
    seen_call = False

    for instruction in _decode(process, _follow_jumps(process, function)):
        if _is_direct_call(instruction):
            this_in_rcx = Register.RCX in this_registers
            this_registers -= _VOLATILE_REGISTERS
            for register in _VOLATILE_REGISTERS:
                lea_targets.pop(register, None)

            if skip_first_call and not seen_call:
                # this is the allocator call, the new object is returned in rax
                this_registers = {Register.RAX}
            elif depth > 0 and this_in_rcx:
                if (inner := _find_vtable(
                        process,
                        instruction.near_branch_target,
                        {Register.RCX},
                        depth=depth - 1,
                )) is not None:
                    vtable = inner

            seen_call = True
            continue

        if instruction.mnemonic == Mnemonic.LEA and instruction.memory_base == Register.RIP:
            lea_targets[instruction.op0_register] = instruction.memory_displacement
            this_registers.discard(instruction.op0_register)
            continue

        if instruction.mnemonic == Mnemonic.MOV:
            # mov [this], reg
            if (
                    instruction.op0_kind == OpKind.MEMORY
                    and instruction.op1_kind == OpKind.REGISTER
                    and instruction.memory_base in this_registers
                    and instruction.memory_index == Register.NONE
                    and instruction.memory_displacement == 0
                    and instruction.op1_register in lea_targets
            ):
                vtable = lea_targets[instruction.op1_register]
                continue

            # mov reg, reg
            if instruction.op0_kind == OpKind.REGISTER and instruction.op1_kind == OpKind.REGISTER:
                if instruction.op1_register in this_registers:
                    this_registers.add(instruction.op0_register)
                else:
                    this_registers.discard(instruction.op0_register)
                lea_targets.pop(instruction.op0_register, None)
                continue

        for used_register in _INFO_FACTORY.info(instruction).used_registers():
            if used_register.access in _WRITE_ACCESSES:
                register = RegisterExt.full_register(used_register.register)
                this_registers.discard(register)
                lea_targets.pop(register, None)

    return vtable


def _get_core_type_from_vtable(process: WindowsProcess, vtable: int) -> CoreType | None:
    """
    the first virtual of every CoreObject is GetCoreType which looks like
    lea rcx, [name]; call RegisterCoreType; mov [static], rax; ...; mov rax, [static]; ret
    """
    get_core_type = _follow_jumps(process, process.read_formatted(vtable, "Q"))

    stores = set()
    static_core_type = None
    for instruction in _decode(process, get_core_type, 0x100):
        if instruction.mnemonic != Mnemonic.MOV or instruction.memory_base != Register.RIP:
            continue

        # mov [static], rax
        if instruction.op0_kind == OpKind.MEMORY and instruction.op1_register == Register.RAX:
            stores.add(instruction.memory_displacement)
        # mov rax, [static]
        elif instruction.op0_kind == OpKind.REGISTER and instruction.op0_register == Register.RAX:
            static_core_type = instruction.memory_displacement

    # if the static isn't both written and read this is not a GetCoreType function
    if static_core_type is None or static_core_type not in stores:
        return None

    core_type_address = process.read_formatted(static_core_type, "Q")

    if core_type_address == 0:
        return None

    return CoreType(address=core_type_address, process=process)


def get_creator_core_type(process: WindowsProcess, creator: int) -> CoreType | None:
    """get the CoreType of the object a CoreObjectFactory creator instantiates"""
    creator_vtable = process.read_formatted(creator, "Q")
    # 0 is the destructor, 1 is Create
    create_function = process.read_formatted(creator_vtable + 8, "Q")

    vtable = _find_vtable(process, create_function, set(), skip_first_call=True)

    if vtable is None:
        return None

    return _get_core_type_from_vtable(process, vtable)


def get_core_object_factory_types(process: WindowsProcess | None = None) -> dict[str, dict[str, int]]:
    """
    get a mapping of core type -> {"namespace": namespace, "type_hash": hash}

    type_hash is the core type hash of the object CoreObjectFactory creates for it
    """
    if process is None:
        process = WindowsProcess.from_name("WizardGraphicalClient.exe")

    factory = _read_rip_global(process, CORE_OBJECT_FACTORY_PATTERN)
    # CoreObjectFactory+8 is a std::map<pair<int, uint>, Creator*>
    head = CoreObjectFactoryNode(address=process.read_formatted(factory + 8, "Q"), process=process)
    nodes = [node for node in read_map_nodes(head) if not node.is_leaf]

    core_types = {}
    for node in sorted(nodes, key=lambda n: (n.core_type, n.namespace)):
        if (core_type := get_creator_core_type(process, node.creator)) is None:
            continue

        core_types[str(node.core_type)] = {
            "namespace": node.namespace,
            # & 0xFFFF_FFFF makes it unsigned
            "type_hash": core_type.hash & 0xFFFF_FFFF,
        }

    return core_types
