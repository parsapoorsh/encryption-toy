BLOCK_SIZE = 16


def block_brackets(n_blocks: int) -> str:
    parts = []
    width = BLOCK_SIZE * 2
    for i in range(1, n_blocks + 1):
        label = f"BLOCK {i}"
        pad = width - 2 - len(label)
        left = pad // 2
        right = pad - left
        parts.append("|" + ("-" * left) + label + ("-" * right) + "|")
    return "".join(parts)


def print_hex(label: str, data: bytes, mark_byte: int | None = None):
    print(f"{label}{data.hex()}")
    if mark_byte is not None:
        print(" " * (len(label) + mark_byte * 2) + "^^")
