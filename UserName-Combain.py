import argparse

def generate_combinations(firstname, lastname):
    combinations = {
        "first": firstname,
        "last": lastname,
        "firstlast": firstname + lastname,
        "first.last": firstname + "." + lastname,
        "last.first": lastname + "." + firstname,
        "lastfirst": lastname + firstname,
        "firstL": firstname + lastname[0],
        "lastF": lastname + firstname[0],
        "firstL2": firstname + lastname[:2],
        "firstL3": firstname + lastname[:3],
        "lastF2": lastname + firstname[:2],
        "lastF3": lastname + firstname[:3],
        "fl": firstname[0] + lastname[0],
        "lf": lastname[0] + firstname[0],
        "l.first": lastname[0] + "." + firstname,
        "f.last": firstname[0] + "." + lastname,
        "first.l": firstname + "." + lastname[0],
        "last.f": lastname + "." + firstname[0]
    }
    return combinations

def process_names_file(input_path, output_path, style):
    with open(input_path, "r") as infile, open(output_path, "w") as outfile:
        for line in infile:
            if not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            firstname, lastname = parts[0].lower(), parts[1].lower()
            combos = generate_combinations(firstname, lastname)
            if style == "all":
                for value in sorted(set(combos.values())):
                    print(value)
                    outfile.write(f"{value}\n")
            elif style in combos:
                print(combos[style])
                outfile.write(f"{combos[style]}\n")
            else:
                print(f"[!] Style '{style}' is not supported. Fuck: {firstname} {lastname}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate username combinations from name list")
    parser.add_argument("-input", required=True, help="Path to input TXT file")
    parser.add_argument("-output", required=True, help="Path to output TXT file")
    parser.add_argument("-style", required=True,
        help="Combination style (first, last, firstlast, first.last, last.first, lastfirst, firstL, lastF, firstL2, firstL3, lastF2, lastF3, fl, lf, l.first, f.last, first.l, last.f, all)")
    args = parser.parse_args()
    process_names_file(args.input, args.output, args.style)
