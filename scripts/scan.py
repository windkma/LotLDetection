"""input is analyzed, never executed."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.models.predictor import LotLPredictor


def print_result(result):
    print("Extracted features: " + " ".join(result["labels"]))
    print("Prediction: " + result["verdict"])
    print()


def print_file_batch(predictor, batch):
    results = predictor.predict_batch([command for _, command in batch])
    for (line_number, command), result in zip(batch, results):
        print(f"[Line {line_number}] {command}")
        print_result(result)


def scan_file(predictor, path):
    """Read one command per nonempty UTF-8 line, in batches of 1,000."""
    batch = []
    total = 0
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            command = line.strip()
            if not command:
                continue
            batch.append((line_number, command))
            total += 1
            if len(batch) == 1000:
                print_file_batch(predictor, batch)
                batch.clear()
    if batch:
        print_file_batch(predictor, batch)
    if total == 0:
        print("No commands found in file.")


def main():
    parser = argparse.ArgumentParser(description="Scan commands with LotlDetection")
    parser.add_argument("--platform", choices=["windows", "linux"], default="windows")
    parser.add_argument("command", nargs="?", help="Command text; omit for the >>> prompt")
    parser.add_argument("--file", type=Path, metavar="PATH", help="UTF-8 TXT file containing one command per line")
    args = parser.parse_args()
    if args.file is not None and args.command is not None:
        parser.error("Use either a command or --file, not both.")
    predictor = LotLPredictor(args.platform)
    if args.file is not None:
        try:
            scan_file(predictor, args.file)
        except (OSError, UnicodeError) as error:
            parser.error(f"Cannot read command file {args.file}: {error}")
        return
    if args.command is not None:
        print_result(predictor.predict(args.command))
        return
    print(f"LotlDetection [{args.platform}] - type exit to quit (multiline quotes supported)")
    while True:
        try:
            line = input(">>> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if line.strip().lower() in {"exit", "quit"}:
            break

        # Accumulate multiline input if quotes are unclosed
        accumulated = [line]
        while True:
            text_so_far = "\n".join(accumulated)
            # Count single and double quotes not escaped
            single_quotes = text_so_far.count("'")
            double_quotes = text_so_far.count('"')
            if single_quotes % 2 == 0 and double_quotes % 2 == 0:
                break
            try:
                continuation = input("... ")
                accumulated.append(continuation)
            except (EOFError, KeyboardInterrupt):
                print()
                break

        command = "\n".join(accumulated).strip()
        if command:
            print_result(predictor.predict(command))


if __name__ == "__main__":
    main()
