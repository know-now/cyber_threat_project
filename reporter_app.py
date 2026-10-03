import os
import time
from datetime import datetime
import pandas as pd
from sqlalchemy import create_engine
import matplotlib.pyplot as plt 
import seaborn as sns
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors 
from apscheduler.schedulers.background import BackgroundScheduler
import warnings
warnings.filterwarnings('ignore')

DB_USER=os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = "postgres_db"
DB_PORT = "5432"
DB_NAME = os.getenv("POSTGRES_DB") or "cyber_threat_db"

engine = create_engine(f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

def generate_charts(df):
    os.makedirs("reports/images", exist_ok=True)
    
    # Threat Landscape
    plt.figure(figsize=(8, 5))
    sns.countplot(data=df, y='attack_type', order=df['attack_type'].value_counts().index, palette='viridis')
    plt.title('Current Threat Landscape (OSINT)', fontsize=14)
    plt.xlabel('Number of Incidents')
    plt.ylabel('Attack Type')
    plt.tight_layout()
    plt.savefig('reports/images/threat_landscape.png', dpi=300)
    plt.close()
    
    #2. Dynamic Risk Matrix (Priorities)
    plt.figure(figsize=(8,5))
    scatter = sns.scatterplot(
        data=df, x='confidence', y='severity',
        size='dynfmic_risk_score', hur='attack_type', 
        sizes
    )

def generate_pdf_report():
    print(f"\n ===[REPORTER] Begining of a report generation: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}===")
    
    try:
        # Extracting top-15 most critical incidents
        query = "SELECT timestamp, source_ip, threat_title, attack_type, severity, confidence FROM threat_logs ORDER BY timestamp DESC LIMIT 15"
        df = pd.read_sql(query, engine)
        
        if df.empty:
            print('[-] Database is empty. Document is not generated.')
            return
        # Creating folder for documents, if it does not exist
        os.makedirs("reports", exist_ok=True)
        report_filename = f"reports/Executive_CTI_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        
        #Setting the style of PDF
        pdf = SimpleDocTemplate(report_filename, pagesize=landscape(letter))
        styles = getSampleStyleSheet()
        elements = []

        #Titles
        title_style = styles['Heading1']
        title_style.alignment = 1
        elements.append(Paragraph("Executive Cyber Threat Intelligence Report", title_style))
        elements.append(Spacer(1,12))
        elements.append(Paragraph(f"<b>Generated on: </b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
        elements.append(Spacer(1, 24))
        
        # Setting of the style for a long text in a table
        cell_style=styles['Normal']
        cell_style.fontSize = 9
        cell_style.leading = 11

        #Preparing data for the table
        table_data = [["Timestamp", "Source IP", "Threat Details (Title)", "Classification", "Severity", "Accuracy"]]
        for index, row in df.iterrows():
            short_time = str(row['timestamp']).split('.')[0]
            accuracy_str = f"{row['confidence']}%" if 'confidence' in row and pd.notnull(row['confidence']) else "N/A"
            title_text = str(row['threat_title'])
            title_paragraph = Paragraph(title_text, cell_style)
            class_paragraph = Paragraph(str(row['attack_type']), cell_style)
            
            table_data.append([short_time, str(row['source_ip']), title_paragraph, class_paragraph, str(row['severity']), accuracy_str])
            
        #Format table
        t = Table(table_data, colWidths=[100, 90, 300, 80, 50, 60])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), 
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.aliceblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elements.append(t)
        pdf.build(elements)
        print(f"[+] Report is successfully generated and saved: {report_filename}")
    except Exception as e:
        print(f"[-] Error while generating PDF: {e}")

if __name__ == "__main__":
    print("===CTI Reporter Service Started===")
    generate_pdf_report()
    #Set up the schedule
    scheduler = BackgroundScheduler()
    scheduler.add_job(generate_pdf_report, 'cron', hour=8, minute=0)
    scheduler.start()
    
    #Infinite loop of working of the microservice
    
    try:
        while True: 
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        
