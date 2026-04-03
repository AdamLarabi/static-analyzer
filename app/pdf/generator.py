import os
from flask import render_template, current_app
from weasyprint import HTML
import datetime

class PDFGenerator:
    @staticmethod
    def generate_report(report_data, output_path=None):
        """
        Generates a PDF report from analysis data.
        :param report_data: Dictionary containing analysis results
        :param output_path: Optional path to save the PDF. If None, returns bytes.
        """
        try:
            # Render HTML template
            html_content = render_template('pdf/report_pdf.html', **report_data)
            
            # Generate PDF
            if output_path:
                HTML(string=html_content).write_pdf(output_path)
                return output_path
            else:
                return HTML(string=html_content).write_pdf()
        except Exception as e:
            current_app.logger.error(f"Error generating PDF: {str(e)}")
            return None
