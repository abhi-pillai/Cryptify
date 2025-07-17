
        
def convert_to_text(input_file, output_file):
    """Converts a binary file to a hex text file."""
    with open(input_file, "rb") as infile, open(output_file, "w") as outfile:
        outfile.write(infile.read().hex())


def convert_from_text(input_file, output_file):
    """Converts a hex text file back to a binary file."""
    with open(input_file, "r") as infile, open(output_file, "wb") as outfile:
        outfile.write(bytes.fromhex(infile.read()))


def save_hex_to_text(binary_data, output_file):
    """Saves binary data as a hex-encoded text file."""
    with open(output_file, "w") as f:
        f.write(binary_data.hex())

