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
    plt.figure(figsize=(8, 5))
    scatter = sns.scatterplot(
        data=df, x='confidence', y='severity',
        size='dynamic_risk_score', hue='attack_type', 
        size=(20, 400), alpha=0.7, palette='tab10'
    )
    plt.title('Dynamic Risk Matrix (Severity vs AI Confidence)', fontsize=14)
    plt.xlabel('AI Confidence (%)')
    plt.ylabel('Base Severity (1-15)')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout() 
    plt.savefig('reports/images/risk_matrix.png', dpi=300)
    plt.close()
    
    #3 Theat Velocity
    plt.figure(figsize=(10, 4))
    df_sorted=df.sort_values('timestamp')
    sns.lineplot(data=df_sorted, x='timestamp', y='threat_velocity_24h', color='darkred', linewidth=2)
    plt.title('Threat Velocity (Cumulative Incidents 24h)', fontsize=14)
    plt.xlabel('Time')
    plt.ylabel('Velocity (Count)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('reports/images/threat_velocity.png', dpi=300)
    plt.close()
    
def generate_pdf_report():
    print(f"\n ===[REPORTER] Begining of a report generation: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}===")
    
    try:
        # Analytics
        query_mart = "SELECT * FROM tableau_mart ORDER BY dynamic_risk_score DESC LIMIT 50"
        df_mart = pd.read_sql(query_mart, engine)
        
        #Request 2: raw logs
        query_raw = "SELECT timestamp, source_ip, threat_title, attack_type, severity, confidence FROM threat_logs ORDER BY timestamp DESC LIMIT 15"
        df_raw = pd.read_sql(query_raw, engine)
        
        if df_mart.empty or df_raw.empty:
            print('[-] Database is missing data. Document is not generated.')
            return
        
        os.makedirs("reports", exist_ok=True)
        generate_charts(df_mart)
        
        report_filename = f"reports/Executive_CTI_Report_{datetime.now().strftime('%Y%m%d_%H%m')}.pdf"
        
        pdf = SimpleDocTemplate(report_filename, pagesize=landscape(letter))
        styles = getSanmleStyleSheet()
        elements = []
        
        #Titles
        title_style = styles['Heading1']
        title_style.alignment = 1
        elements.append(Paragraph("Executive Cyber Threat Intelligence Report", title_style))
        elements.append(Paragraph(f"<b>Generated on: </b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
        elements.append(Spacer(1, 10))
        
        elements.append(Image('reports/images/risk_matrix.png', width=450, height=280))
        elements.append(Spacer(1, 10))
        elements.append(Image('reports/images/threat_landscape.png', width=450, height=280))
        
        elements.append(PageBreak())
        
        # Page 2: Top critical threats
        elements.append(Paragraph("Top Critical Action Items (Dynamic Risk Analytics)", title_style))
        elements.append(Image('reports/images/threat_velocity.png', width=600, height=200))
        elements.append(Spacer(1, 15))
        
        # Setting of the style for a long text in a table
        cell_style=styles['Normal']
        cell_style.fontSize = 8
        cell_style.leading = 10
        
        mart_table_data = [["Timestamp", "Threat Details (Title)", "Classification", "Base Severity", "AI Confidence", "Dynamic Risk"]]
        for index, row in df_mart.head(10).iterrows():
            short_time = str(row['timestamp']).split('.')[0]
            accuracy_str = f"{row['confidence']}%"
            mart_table_data.append([
                short_time, Paragraph(str(row['threat_title']), cell_style), Paragraph(str(row['attack_type']), cell_style), 
                str(row['severity']), accuracy_str, str(row['dynamic_risk_score'])
            ])
        t_mart = Table(mart_table_data, colWidth=[90, 300, 80, 70, 70, 70])
        t_mart.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), 
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.aliceblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(t_mart)
        elements.append(PageBreak())
        
        # Page 3.
        elements.append(Paragraph("System Raw Threat Logs (Last 15 Events)", title_style))
        elements.append(Spacer(1, 15))
        
        
        #Preparing data for the table
        raw_table_data = [["Timestamp", "Source IP", "Threat Details (Title)", "Classification", "Severity", "Accuracy"]]
        for index, row in df.iterrows():
            short_time = str(row['timestamp']).split('.')[0]
            accuracy_str = f"{row['confidence']}%" if 'confidence' in row and pd.notnull(row['confidence']) else "N/A"
            raw_table_data.append([
                short_time, str(row['source_ip']),  Paragraph(str(row['threat_title']), cell_style),
                Paragraph(str(row['attack_type']), cell_style), str(row['severity']), accuracy_str
            ])
            
            
            title_text = str(row['threat_title'])
            title_paragraph = Paragraph(title_text, cell_style)
            class_paragraph = Paragraph(str(row['attack_type']), cell_style)
            
            table_data.append([short_time, str(row['source_ip']), title_paragraph, class_paragraph, str(row['severity']), accuracy_str])
            
        #Format table
        t_raw = Table(table_data, colWidths=[100, 90, 300, 80, 50, 60])
        t_raw.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), 
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.aliceblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elements.append(t_raw)
        pdf.build(elements)
        print(f"[+] Advanced Visual Report successfully generated: {report_filename}")
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
        
