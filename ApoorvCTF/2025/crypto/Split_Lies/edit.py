from PIL import Image
import numpy as np

def xor_images(image_path1, image_path2, output_path):
    # Mở hai ảnh
    img1 = Image.open(image_path1).convert('RGBA')
    img2 = Image.open(image_path2).convert('RGBA')

    # Đảm bảo hai ảnh có cùng kích thước
    if img1.size != img2.size:
        raise ValueError("Ảnh phải có cùng kích thước để thực hiện XOR")

    # Chuyển ảnh thành mảng numpy
    img1_array = np.array(img1)
    img2_array = np.array(img2)

    # Thực hiện phép XOR pixel theo từng kênh màu
    xor_result = np.bitwise_xor(img1_array, img2_array)

    # Chuyển mảng kết quả thành ảnh
    result_img = Image.fromarray(xor_result, 'RGB')

    # Lưu ảnh kết quả
    result_img.save(output_path)
    print(f"Ảnh kết quả đã được lưu tại: {output_path}")

# Sử dụng hàm
xor_images('part1.png', 'part2.png', 'output.png')
