"""
Fix QR code display by generating a PNG image instead of terminal output.
Run: python cli/console.py enroll <device> --qr-image
"""

import sys
import qrcode

# Quick test to generate QR as image
def generate_qr_image(data, filename):
    """Generate QR code as PNG image."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
    print(f"✔ QR code saved to: {filename}")
    print(f"  Open the image and scan with your WireGuard app!")

if __name__ == "__main__":
    # Test config string
    test_config = """[Interface]
PrivateKey=test123
Address=10.8.0.2/24

[Peer]
PublicKey=server123
Endpoint=1.2.3.4:51820
AllowedIPs=0.0.0.0/0"""
    
    generate_qr_image(test_config, "test_qr.png")
