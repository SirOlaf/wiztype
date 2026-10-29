import re
import struct

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

from .memory import CoreObjectFactoryNode
from .type_tree import read_map_nodes

# mov rax, [rip+factory]; mov ebx, edx; movzx edx, r8b; mov r9, [rax+8]
# this is the start of CoreObjectFactory::CreateCoreObject
CORE_OBJECT_FACTORY_PATTERN = rb"\x48\x8B\x05....\x8B\xDA\x41\x0F\xB6\xD0\x4C\x8B\x48\x08"

MODULE_NAME = "WizardGraphicalClient.exe"

# lea rcx, [rip+name]; call rel32
# this is how GetCoreType passes its name to RegisterCoreType
_REGISTER_CORE_TYPE_CALL_PATTERN = re.compile(rb"\x48\x8D\x0D(.{4})\xE8(.{4})", re.DOTALL)

# offsets into a CoreTemplate vtable
# the type of the objects made from the template, CreateCoreObject is called with this
_TEMPLATE_TYPE_SLOT = 0x70
# the category the template belongs to, this is byte 5 of the template's gid
_TEMPLATE_CATEGORY_SLOT = 0x80

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
    mov_addr = process.scan_one(pattern, module=MODULE_NAME)

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


def core_type_hash(name: str) -> int:
    """the djb2 variant RegisterCoreType hashes core type names with"""
    result = 0x1505
    for char in name.encode():
        result = (result * 33 + char) & 0xFFFF_FFFF

    return result & 0x7FFF_FFFF


def _get_core_type_name_from_vtable(process: WindowsProcess, vtable: int) -> str | None:
    """
    the first virtual of every CoreObject is GetCoreType which looks like
    lea rcx, [name]; call RegisterCoreType; mov [static], rax; ...; mov rax, [static]; ret

    the static is only filled the first time GetCoreType is called so the name is
    read from the code instead
    """
    get_core_type = _follow_jumps(process, process.read_formatted(vtable, "Q"))

    name = None
    call_name = None
    register_name = None
    stores = set()
    static_core_type = None
    for instruction in _decode(process, get_core_type, 0x100):
        # lea rcx, [name]
        if (
                instruction.mnemonic == Mnemonic.LEA
                and instruction.memory_base == Register.RIP
                and instruction.op0_register == Register.RCX
        ):
            name = instruction.memory_displacement
            continue

        if _is_direct_call(instruction):
            call_name, name = name, None
            continue

        if instruction.mnemonic != Mnemonic.MOV or instruction.memory_base != Register.RIP:
            continue

        # mov [static], rax
        if instruction.op0_kind == OpKind.MEMORY and instruction.op1_register == Register.RAX:
            stores.add(instruction.memory_displacement)
            # the call right before the store is RegisterCoreType
            register_name = call_name
        # mov rax, [static]
        elif instruction.op0_kind == OpKind.REGISTER and instruction.op0_register == Register.RAX:
            static_core_type = instruction.memory_displacement

    # if the static isn't both written and read this is not a GetCoreType function
    if static_core_type is None or static_core_type not in stores or register_name is None:
        return None

    return process.read_memory(register_name, 0x100).split(b"\0")[0].decode()


def get_creator_core_type_name(process: WindowsProcess, creator: int) -> str | None:
    """get the core type name of the object a CoreObjectFactory creator instantiates"""
    creator_vtable = process.read_formatted(creator, "Q")
    # 0 is the destructor, 1 is Create
    create_function = process.read_formatted(creator_vtable + 8, "Q")

    vtable = _find_vtable(process, create_function, set(), skip_first_call=True)

    if vtable is None:
        return None

    return _get_core_type_name_from_vtable(process, vtable)


class _Section:
    def __init__(self, address: int, data: bytes):
        self.address = address
        self.data = data

    def __contains__(self, address: int) -> bool:
        return self.address <= address < self.address + len(self.data)

    def read(self, address: int, size: int) -> bytes:
        offset = address - self.address
        return self.data[offset:offset + size]

    def follow_jumps(self, address: int) -> int:
        """follow jmp rel32 thunks to the real function"""
        while address in self and self.read(address, 1) == b"\xE9":
            address += 5 + struct.unpack("<i", self.read(address + 1, 4))[0]

        return address


def _read_sections(process: WindowsProcess) -> dict[str, _Section]:
    """read the sections of the main module"""
    base = process.get_module_named(MODULE_NAME).lpBaseOfDll

    pe_header = base + process.read_formatted(base + 0x3C, "I")
    section_count = process.read_formatted(pe_header + 6, "H")
    optional_header_size = process.read_formatted(pe_header + 20, "H")

    sections = {}
    section_header = pe_header + 24 + optional_header_size
    for _ in range(section_count):
        name, virtual_size, virtual_address = struct.unpack(
            "<8sII", process.read_memory(section_header, 16)
        )
        address = base + virtual_address
        sections[name.rstrip(b"\0").decode()] = _Section(address, process.read_memory(address, virtual_size))
        section_header += 40

    return sections


def _read_byte_returned(process: WindowsProcess, text: _Section, function: int) -> int | None:
    """read the byte a function like `mov al, 3; ret` or `movzx eax, byte [static]; ret` returns"""
    function = text.follow_jumps(function)
    instruction = Decoder(64, text.read(function, 16), ip=function).decode()

    match instruction.mnemonic:
        # mov al, imm8
        case Mnemonic.MOV if instruction.op0_register == Register.AL and instruction.op1_kind == OpKind.IMMEDIATE8:
            return instruction.immediate8
        # movzx eax, byte [static]
        case Mnemonic.MOVZX if instruction.memory_base == Register.RIP:
            return process.read_formatted(instruction.memory_displacement, "B")
        # xor al, al
        case Mnemonic.XOR if instruction.op0_register == instruction.op1_register != Register.NONE:
            return 0

    return None


def get_template_categories(process: WindowsProcess) -> dict[int, int]:
    """
    get a mapping of template type -> category for every CoreTemplate subclass

    the category is byte 5 of a template's gid, e.g. every WizItemTemplate subclass is
    category 9 (ItemTemplate) while their template types differ
    """
    sections = _read_sections(process)
    text = sections[".text"]
    rdata = sections[".rdata"]

    # name address -> RegisterCoreType call sites
    register_calls = []
    for match in _REGISTER_CORE_TYPE_CALL_PATTERN.finditer(text.data):
        call = text.address + match.start() + 7
        name = call + struct.unpack("<i", match.group(1))[0]
        target = call + 5 + struct.unpack("<i", match.group(2))[0]
        register_calls.append((call, name, target))

    # CoreTemplate's GetCoreType tells us which function RegisterCoreType is
    core_template_name = b"CoreTemplate\0"
    core_template_calls = [
        (call, target) for call, name, target in register_calls
        if name in rdata and rdata.read(name, len(core_template_name)) == core_template_name
    ]
    if len(core_template_calls) != 1:
        raise ValueError(f"expected one CoreTemplate GetCoreType, found {len(core_template_calls)}")

    core_template_call, register_core_type = core_template_calls[0]

    def get_function_start(address: int) -> int:
        # GetCoreType functions are small and padded with int3
        start = address
        while start > address - 0x100 and text.read(start - 1, 1) != b"\xCC":
            start -= 1

        return start

    # GetCoreType -> the parent GetCoreType it calls first
    parents: dict[int, int | None] = {}
    for call, _, target in register_calls:
        if target != register_core_type:
            continue

        start = get_function_start(call)
        parent = None
        for instruction in Decoder(64, text.read(start, call - start), ip=start):
            if _is_direct_call(instruction):
                parent = text.follow_jumps(instruction.near_branch_target)
                break

        parents[start] = parent

    core_template = get_function_start(core_template_call)

    def is_template(get_core_type: int) -> bool:
        seen = set()
        while (get_core_type := parents.get(get_core_type)) is not None and get_core_type not in seen:
            if get_core_type == core_template:
                return True

            seen.add(get_core_type)

        return False

    templates = {get_core_type for get_core_type in parents if is_template(get_core_type)}

    # every vtable starts with GetCoreType
    vtable_entries = memoryview(rdata.data[:len(rdata.data) // 8 * 8]).cast("Q")
    template_entries = {
        entry for entry in set(vtable_entries)
        if entry in text and text.follow_jumps(entry) in templates
    }

    categories: dict[int, set[int]] = {}
    for index, entry in enumerate(vtable_entries):
        if entry not in template_entries:
            continue

        vtable = rdata.address + index * 8
        template_type = _read_byte_returned(
            process, text, struct.unpack("<Q", rdata.read(vtable + _TEMPLATE_TYPE_SLOT, 8))[0]
        )
        category = _read_byte_returned(
            process, text, struct.unpack("<Q", rdata.read(vtable + _TEMPLATE_CATEGORY_SLOT, 8))[0]
        )

        if template_type is not None and category is not None:
            categories.setdefault(template_type, set()).add(category)

    # only keep template types every template agrees on
    return {
        template_type: category_set.pop()
        for template_type, category_set in sorted(categories.items())
        if len(category_set) == 1
    }


def get_core_object_factory_types(process: WindowsProcess | None = None) -> dict[str, dict[str, int | None]]:
    """
    get a mapping of core type -> {"category": category, "type_hash": hash}

    category is byte 5 of the gid of the templates objects of this core type are made from,
    it is None if there is no template for the core type

    type_hash is the core type hash of the object CoreObjectFactory creates for it
    """
    if process is None:
        process = WindowsProcess.from_name(MODULE_NAME)

    categories = get_template_categories(process)

    factory = _read_rip_global(process, CORE_OBJECT_FACTORY_PATTERN)
    # CoreObjectFactory+8 is a std::map<pair<int, uint>, Creator*>
    head = CoreObjectFactoryNode(address=process.read_formatted(factory + 8, "Q"), process=process)
    nodes = [node for node in read_map_nodes(head) if not node.is_leaf]

    core_types = {}
    for node in sorted(nodes, key=lambda n: n.core_type):
        if (name := get_creator_core_type_name(process, node.creator)) is None:
            continue

        core_types[str(node.core_type)] = {
            "category": categories.get(node.core_type),
            "type_hash": core_type_hash(name),
        }

    return core_types
