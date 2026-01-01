
import pypdf
import sys

def extract_text(pdf_path, pages=20):
    try:
        reader = pypdf.PdfReader(pdf_path)
        text = ""
        max_pages = min(len(reader.pages), pages)
        for i in range(max_pages):
            page = reader.pages[i]
            text += page.extract_text() + "\n"
        
        with open("pdf_summary.txt", "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Successfully extracted {max_pages} pages to pdf_summary.txt")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    extract_text("Attacking_and_Defending_ActiveDirectory .pdf")
