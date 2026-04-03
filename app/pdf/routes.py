from flask import Blueprint, send_file, current_app, abort, render_template, make_response
from flask_login import login_required, current_user
from app.models.ticket import Ticket
from app.pdf.generator import PDFGenerator
from io import BytesIO

pdf_bp = Blueprint('pdf', __name__, template_folder='templates')

@pdf_bp.route('/generate/<int:ticket_id>', methods=['POST'])
@login_required
def generate(ticket_id):
    from flask import request
    import base64
    from datetime import datetime

    ticket = Ticket.query.get_or_404(ticket_id)
    
    if not current_user.has_permission('generate_pdf'):
        abort(403)
        
    client_name = request.form.get('client_name', '').strip()
    
    logo_data_uri = None
    if 'logo' in request.files:
        logo_file = request.files['logo']
        if logo_file.filename:
            mime = logo_file.content_type
            encoded = base64.b64encode(logo_file.read()).decode('utf-8')
            logo_data_uri = f"data:{mime};base64,{encoded}"
            
    report_data = {
        'ticket': ticket,
        'data': ticket.result,
        'client_name': client_name,
        'logo_data_uri': logo_data_uri,
        'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    }
    
    try:
        pdf_bytes = PDFGenerator.generate_report(report_data)
        if pdf_bytes:
            pdf_stream = BytesIO(pdf_bytes)
            filename = f"report_DP-{ticket_id:05d}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
            return send_file(
                pdf_stream,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )
        else:
            abort(500, description="PDF generation failed.")
    except Exception as e:
        current_app.logger.error(f"PDF generation error: {str(e)}")
        abort(500)

