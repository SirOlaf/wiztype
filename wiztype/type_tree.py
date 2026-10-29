from memobj import WindowsProcess

from .memory import HashNode

HASH_CALL_PATTERN = rb"\xE8....\x48\xBD........\x48\x3B\x38\x74\x12"


def _get_root_node(process: WindowsProcess) -> HashNode:
    # for now this pattern is unique in WizardGraphicalClient.exe
    # note that there is an ambiguous match in the bug reporter,
    # which is why we restrict the scan here
    hash_call_addr = process.scan_memory(HASH_CALL_PATTERN, module="WizardGraphicalClient.exe")[0]

    # E8 [73 46 00 00]
    call_offset = process.read_formatted(hash_call_addr + 1, "i")

    # 5 is the length of the call instruction
    call_addr = hash_call_addr + call_offset + 5

    # 48 8B 05 [D8 41 EC 01]
    hash_tree_offset = process.read_formatted(call_addr + 44, "i")

    # 41 is start of the lea instruction and 7 is the length of it
    hash_tree_addr = call_addr + 41 + hash_tree_offset + 7

    pointer = process.read_formatted(hash_tree_addr, "Q")
    address = process.read_formatted(pointer, "Q")

    return HashNode(address=address, process=process)


def _get_children_nodes(node, nodes: set):
    nodes.add(node)

    if node.is_leaf is False:
        if left_node := node.left:
            if left_node not in nodes:
                _get_children_nodes(left_node, nodes)
        if right_node := node.right:
            if right_node not in nodes:
                _get_children_nodes(right_node, nodes)

    return nodes


def read_map_nodes(head_node) -> set:
    """read all nodes of a msvc std::map given its head node"""
    nodes = set()

    first_node = head_node.parent
    return _get_children_nodes(first_node, nodes)


def get_hash_nodes(process: WindowsProcess) -> set[HashNode]:
    root_node = _get_root_node(process)
    return read_map_nodes(root_node)


def get_type_tree() -> dict[str, HashNode]:
    process = WindowsProcess.from_name("WizardGraphicalClient.exe")

    nodes = get_hash_nodes(process)

    hash_map = {}

    for node in nodes:
        if node.is_leaf:
            continue

        # aliases point at an already registered type, see get_type_aliases
        if node.hash != node.node_data.hash:
            continue

        hash_map[node.node_data.name] = node

    return hash_map


def get_type_aliases(process: WindowsProcess | None = None) -> dict[str, int]:
    """
    get a mapping of alias hash -> hash of the type it resolves to

    aliases are extra keys in the type hash map that point at an already registered
    type, the serializer resolves them like any other hash
    note that only the hash of an alias' name is stored, not the name itself
    """
    if process is None:
        process = WindowsProcess.from_name("WizardGraphicalClient.exe")

    aliases = {}

    for node in get_hash_nodes(process):
        if node.is_leaf:
            continue

        # & 0xFFFF_FFFF makes it unsigned
        alias_hash = node.hash & 0xFFFF_FFFF
        type_hash = node.node_data.hash & 0xFFFF_FFFF

        if alias_hash != type_hash:
            aliases[str(alias_hash)] = type_hash

    return dict(sorted(aliases.items(), key=lambda item: int(item[0])))
