import PyPDF2
from PIL import Image
import pytesseract
import io

def extract_text_from_pdf(file):
    """Extract text from a PDF file."""
    pdf_reader = PyPDF2.PdfReader(file)
    text = ""
    for page in pdf_reader.pages:
        text += page.extract_text()
    return text

def extract_text_from_image(file):
    """Extract text from an image file using OCR."""
    image = Image.open(file)
    text = pytesseract.image_to_string(image)
    return text

def extract_text_from_file(file, file_type):
    """Extract text from either PDF or image based on file type."""
    if file_type == "application/pdf":
        return extract_text_from_pdf(file)
    elif file_type in ["image/png", "image/jpeg", "image/jpg"]:
        return extract_text_from_image(file)
    else:
        raise ValueError("Unsupported file type")