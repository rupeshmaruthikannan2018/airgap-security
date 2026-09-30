from pathlib import Path


def extract_code_context(
    file_path,
    start_line,
    end_line,
    context_lines=5
):
    file_path = Path(file_path)

    if not file_path.exists():
        return None

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as f:
            lines = f.readlines()

    except OSError:
        return None

    start = max(
        1,
        start_line - context_lines
    )

    end = min(
        len(lines),
        end_line + context_lines
    )

    selected_lines = []

    for number in range(start, end + 1):

        selected_lines.append(
            f"{number:4}: {lines[number - 1].rstrip()}"
        )

    return "\n".join(selected_lines)