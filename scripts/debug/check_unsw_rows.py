import csv

FILE = "data/raw/UNSW_NB15/UNSW-NB15_1.csv"

counts = {}
bad_rows = []
total = 0

with open(
    FILE,
    "r",
    encoding="utf-8",
    errors="replace",
    newline=""
) as f:

    reader = csv.reader(f)

    for line_number, row in enumerate(reader, start=1):

        total += 1

        field_count = len(row)

        counts[field_count] = counts.get(field_count, 0) + 1

        if field_count != 49 and len(bad_rows) < 10:
            bad_rows.append(
                (line_number, field_count, row)
            )

print("=" * 70)
print("UNSW-NB15 RAW ROW CHECK")
print("=" * 70)

print("FILE:", FILE)
print("TOTAL ROWS:", total)

print("\nFIELD COUNT DISTRIBUTION:")

for count in sorted(counts):
    print(
        "FIELDS:",
        count,
        "| ROWS:",
        counts[count]
    )

print("\nFIRST BAD ROWS:")

if not bad_rows:
    print("NONE")
else:
    for line_number, field_count, row in bad_rows:
        print("\nLINE:", line_number)
        print("FIELD COUNT:", field_count)
        print("ROW:", row)