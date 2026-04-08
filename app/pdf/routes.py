from flask import Blueprint, send_file, current_app, abort, render_template, make_response
from flask_login import login_required, current_user
from app.models.ticket import Ticket
from app.pdf.generator import PDFGenerator
from io import BytesIO
import base64
from PIL import Image

pdf_bp = Blueprint('pdf', __name__, template_folder='templates', url_prefix='/pdf')

@pdf_bp.route('/generate/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def generate(ticket_id):
    from flask import request
    from datetime import datetime

    ticket = Ticket.query.get_or_404(ticket_id)
    
    if not current_user.has_permission('generate_pdf'):
        abort(403)
        
    if not ticket.result:
        abort(404, description="Ticket has no analysis data.")
        
    client_name = request.form.get('client_name', '').strip()
    
    logo_data_uri = None
    if 'logo' in request.files:
        logo_file = request.files['logo']
        if logo_file.filename:
            try:
                img = Image.open(logo_file).convert("RGBA")
                # Flatten transparency onto white background for PDF compatibility
                background = Image.new("RGB", img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[3])
                buf = BytesIO()
                background.save(buf, format="PNG")
                buf.seek(0)
                encoded = base64.b64encode(buf.read()).decode('utf-8')
                logo_data_uri = f"data:image/png;base64,{encoded}"
            except Exception as e:
                current_app.logger.warning(f"Logo processing failed: {e}. Skipping logo.")
            
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
            
            # Formattage demandé : DATAPROTECT-[CLIENT]-[ID].pdf
            safe_client = "".join(x for x in client_name if x.isalnum() or x in "-_").strip() or "ANONYME"
            filename = f"DATAPROTECT-{safe_client.upper()}-{ticket_id:05d}.pdf"
            
            return send_file(
                pdf_stream,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )
        else:
            abort(500, description="PDF generation failed.")
    except Exception as e:
        current_app.logger.error(f"PDF generation error for ticket {ticket_id}: {str(e)}")
        import traceback
        current_app.logger.error(traceback.format_exc())
        return f"<h1>Erreur 500</h1><p>Détails : {str(e)}</p>", 500
