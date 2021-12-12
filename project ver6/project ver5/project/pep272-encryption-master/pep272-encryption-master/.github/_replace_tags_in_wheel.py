"""

"""

import hashlib
import base64
import sys
import zipfile

HASH = "sha512"
WHEEL_SUFFIX = ".dist-info/WHEEL"
RECORD_SUFFIX = ".dist-info/RECORD"


def wheel_hash(data):
    return base64.urlsafe_b64encode(hashlib.new(HASH, data).digest()) \
        .decode().replace("=", "")


if __name__ == '__main__':
    infile = sys.argv[1]
    outfile = sys.argv[2]
    tags = sys.argv[3].split(",")

    wheel_file_name = ""
    wheel_file_content = ""

    record_name = ""
    record_data = {}

    with zipfile.ZipFile(infile) as inf:
        with zipfile.ZipFile(outfile, "w") as outf:
            for file in inf.infolist():
                name = file.filename
                if not name.endswith("WHEEL") and not name.endswith("RECORD"):
                    print(f"Copying {name}")
                    buffer = inf.read(name)
                    record_data[name] = (wheel_hash(buffer),
                                                  len(buffer))
                    outf.writestr(name, buffer)
                elif name.endswith("WHEEL"):
                    wheel_file_name = name
                    wheel_file_content = inf.read(file.filename).decode()
                elif name.endswith("RECORD"):
                    record_name = name
                    record_data[record_name] = ("", "")

            wheel_out = ""
            for line in wheel_file_content.splitlines():
                if not line.startswith("Tag: "):
                    wheel_out += line + "\n"
            for tag in tags:
                wheel_out += 'Tag: {tag}\n'

            print(f"Writing {wheel_file_name}")
            outf.writestr(wheel_file_name, wheel_out)

            record_data[wheel_file_name] = (wheel_hash(wheel_out.encode()),
                                            len(wheel_out))

            record_out = ""
            for filename, (digest, length) in record_data.items():
                record_out += f"{filename},{digest},{length}\n"

            print(f"Writing {record_name}")
            outf.writestr(record_name, record_out)





