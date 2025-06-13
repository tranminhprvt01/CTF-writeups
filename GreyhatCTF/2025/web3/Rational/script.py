import os

def combine_files_to_txt(root_dir, output_file):
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                # Ghi đường dẫn tương đối từ thư mục gốc
                relative_path = os.path.relpath(file_path, root_dir)
                outfile.write(f"Path: {relative_path}\n")
                outfile.write("Content:\n")
                try:
                    with open(file_path, 'r', encoding='utf-8') as infile:
                        content = infile.read()
                        outfile.write(content + "\n")
                except Exception as e:
                    outfile.write(f"Error reading file: {e}\n")
                outfile.write("\n" + "="*50 + "\n\n")

# Thư mục gốc và file đầu ra
root_directory = "./dist-rational"  # Thư mục hiện tại, bạn có thể thay bằng đường dẫn cụ thể
output_txt = "combined_files.txt"

combine_files_to_txt(root_directory, output_txt)
print(f"All files have been combined into {output_txt}")