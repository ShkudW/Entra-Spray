import argparse
import os

def generate_combinations(firstname, lastname):
    combinations = {
        "first": firstname,
        "last": lastname,
        "firstlast": firstname + lastname,
        "first.last": firstname + "." + lastname,
        "last.first": lastname + "." + firstname,
        "lastfirst": lastname + firstname,
        "firstL": firstname + lastname[0] if lastname else firstname,
        "lastF": lastname + firstname[0] if firstname else lastname,
        "firstL2": firstname + lastname[:2],
        "firstL3": firstname + lastname[:3],
        "lastF2": lastname + firstname[:2],
        "lastF3": lastname + firstname[:3],
        "fl": (firstname[0] if firstname else "") + (lastname[0] if lastname else ""),
        "lf": (lastname[0] if lastname else "") + (firstname[0] if firstname else ""),
        "l.first": (lastname[0] if lastname else "") + "." + firstname,
        "f.last": (firstname[0] if firstname else "") + "." + lastname,
        "first.l": firstname + "." + (lastname[0] if lastname else ""),
        "last.f": lastname + "." + (firstname[0] if firstname else "")
    }
    return combinations

def clean_string(text):

    text = text.replace('\u200e', '').replace('\u200f', '').replace('\ufeff', '')

    return "".join(char for char in text if char.isprintable()).strip()

def process_names_file(input_path, output_path, style, tenantname):
    with open(input_path, "r", encoding="utf-8-sig") as infile, open(output_path, "w", encoding="utf-8") as outfile:
        for line in infile:

            cleaned_line = clean_string(line)
            if not cleaned_line:
                continue

            parts = cleaned_line.split()
            if len(parts) < 2:
                continue

            firstname, lastname = parts[0].lower(), parts[1].lower()
            combos = generate_combinations(firstname, lastname)

            tenant = clean_string(tenantname)

            if style == "all":
                for value in sorted(set(combos.values())):
                    username = value + tenant if tenant else value
                    print(username)
                    outfile.write(f"{username}\n")
            elif style in combos:
                username = combos[style] + tenant if tenant else combos[style]
                print(username)
                outfile.write(f"{username}\n")
            else:
                print(f"[!] Style '{style}' is not supported. Skipping: {firstname} {lastname}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate username combinations from name list")
    parser.add_argument("-input", required=True, help="Path to input TXT file")
    parser.add_argument("-output", required=True, help="Path to output TXT file")
    parser.add_argument("-style", required=True, help="Combination style or 'all'")
    parser.add_argument("-tenantname", required=False, default="", help="Tenant domain suffix (e.g. @ggg.com)")

    args = parser.parse_args()
    process_names_file(args.input, args.output, args.style, args.tenantname)
