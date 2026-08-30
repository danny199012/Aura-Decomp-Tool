import struct

def create_minimal_ico():
    """Create a minimal valid ICO file (16x16, 32-bit PNG-like icon)"""
    
    # ICO Header: Reserved(2) + Type(2) + Count(2)
    header = struct.pack('<HHH', 0, 1, 1)
    
    # Image Entry: Width(1) + Height(1) + ColorCount(1) + Reserved(1) + 
    #              Planes(2) + BPP(2) + SizeBytes(4) + Offset(4)
    width = 16
    height = 32  # doubled for alpha channel (OR of color and alpha masks)
    size_bytes = 40 + (width * height * 4)  # BITMAPINFOHEADER + pixels
    offset = 6 + 16  # header + image entry
    
    image_entry = struct.pack('<BBBBHHII', 
        width,      # width
        height,     # height  
        0,          # color count
        0,          # reserved
        1,          # color planes
        32,         # bits per pixel
        size_bytes, # size of bytes
        offset      # offset
    )
    
    # BITMAPINFOHEADER (40 bytes): 
    # biSize(4), biWidth(4), biHeight(4), biPlanes(2), biBitCount(2),
    # biCompression(4), biSizeImage(4), biXPelsPerMeter(4), biYPelsPerMeter(4), biClrUsed(4), biClrImportant(4)
    dib_header = struct.pack('<IiiHHiIIiii',
        40,           # header size
        width,        # width
        height * 2,   # height (doubled for AND mask)
        1,            # color planes
        32,           # bits per pixel
        0,            # compression
        size_bytes - 40,  # image size
        0,            # XPelsPerMeter
        0,            # YPelsPerMeter
        0,            # colors used
        0,            # important colors
    )
    
    # Pixel data (16x16 RGBA - semi-transparent blue)
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            b = 50
            g = 100  
            r = 200
            a = 255 if (x + y) % 2 == 0 else 200
            pixels.extend([b, g, r, a])
    
    # Write ICO file
    with open('src-tauri/icons/icon.ico', 'wb') as f:
        f.write(header)
        f.write(image_entry)
        f.write(dib_header)
        f.write(bytes(pixels))
    
    print(f"Created icon.ico ({len(header + image_entry + dib_header + bytes(pixels))} bytes)")

create_minimal_ico()