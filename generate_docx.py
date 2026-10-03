import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def add_hyperlink(paragraph, url, text, color="0D6EFD", underline=True):
    # This gets access to the document.xml.rels file and gets a new relation id value
    part = paragraph.part
    r_id = part.relate_to(url, docx.opc.constants.RELATIONSHIP_TYPE.HYPERLINK, is_external=True)

    # Create the w:hyperlink tag and add needed values
    hyperlink = OxmlElement('w:hyperlink')
    hyperlink.set(qn('r:id'), r_id)

    # Create a w:r
    new_run = OxmlElement('w:r')
    rPr = OxmlElement('w:rPr')

    if color:
        c = OxmlElement('w:color')
        c.set(qn('w:val'), color)
        rPr.append(c)

    if underline:
        u = OxmlElement('w:u')
        u.set(qn('w:val'), 'single')
        rPr.append(u)

    new_run.append(rPr)
    new_run.text = text
    hyperlink.append(new_run)
    paragraph._p.append(hyperlink)
    return hyperlink

def create_reflection_docx():
    doc = docx.Document()
    
    # Page Margins (0.65 in)
    for section in doc.sections:
        section.top_margin = Inches(0.65)
        section.bottom_margin = Inches(0.65)
        section.left_margin = Inches(0.65)
        section.right_margin = Inches(0.65)
        
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(10)
    normal_style.font.color.rgb = RGBColor(0x22, 0x22, 0x22)
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(3)

    # Document Header
    p_title = doc.add_paragraph()
    r_title = p_title.add_run("Computer Networks — Transport Layer (Assignment 2)")
    r_title.font.name = 'Calibri'
    r_title.font.size = Pt(16)
    r_title.font.bold = True
    r_title.font.color.rgb = RGBColor(0x0F, 0x4C, 0x81)
    p_title.paragraph_format.space_after = Pt(2)

    p_sub = doc.add_paragraph()
    r_sub = p_sub.add_run("Dual-Panel Activity & Transport-Layer Protocol Visualizer (L4 / L7 Extension)")
    r_sub.font.size = Pt(11.5)
    r_sub.font.bold = True
    r_sub.font.color.rgb = RGBColor(0x31, 0x97, 0x95)
    p_sub.paragraph_format.space_after = Pt(6)

    # Metadata Table
    meta_table = doc.add_table(rows=3, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    
    # Cell 0,0: Author
    p = meta_table.rows[0].cells[0].paragraphs[0]
    p.add_run("Author / Student: ").bold = True
    p.add_run("Jitul Roy")
    set_cell_background(meta_table.rows[0].cells[0], "F2F5F8")

    # Cell 0,1: Roll No
    p = meta_table.rows[0].cells[1].paragraphs[0]
    p.add_run("Roll Number: ").bold = True
    p.add_run("202402021026")
    set_cell_background(meta_table.rows[0].cells[1], "F2F5F8")

    # Cell 1,0: Live Demo
    p = meta_table.rows[1].cells[0].paragraphs[0]
    p.add_run("Live Working Demo: ").bold = True
    add_hyperlink(p, "https://application-layer-six.vercel.app/", "https://application-layer-six.vercel.app/")
    set_cell_background(meta_table.rows[1].cells[0], "F2F5F8")

    # Cell 1,1: GitHub Repo
    p = meta_table.rows[1].cells[1].paragraphs[0]
    p.add_run("GitHub Repository: ").bold = True
    add_hyperlink(p, "https://github.com/zitulroy/Application-layer", "https://github.com/zitulroy/Application-layer")
    set_cell_background(meta_table.rows[1].cells[1], "F2F5F8")

    # Cell 2,0: AI Platform
    p = meta_table.rows[2].cells[0].paragraphs[0]
    p.add_run("AI Platform & Model: ").bold = True
    p.add_run("Google Antigravity / Gemini 3.8 Flash (High)")
    set_cell_background(meta_table.rows[2].cells[0], "F2F5F8")

    # Cell 2,1: Prerequisite
    p = meta_table.rows[2].cells[1].paragraphs[0]
    p.add_run("Prerequisite: ").bold = True
    p.add_run("Working Assignment 1 (Application Layer)")
    set_cell_background(meta_table.rows[2].cells[1], "F2F5F8")

    for row in meta_table.rows:
        for cell in row.cells:
            cell.paragraphs[0].paragraph_format.space_after = Pt(2)
            cell.paragraphs[0].paragraph_format.line_spacing = 1.1
            for run in cell.paragraphs[0].runs:
                run.font.size = Pt(9)

    doc.add_paragraph().paragraph_format.space_after = Pt(4)

    def add_h1(text):
        h = doc.add_paragraph()
        r = h.add_run(text)
        r.font.size = Pt(11.5)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0x0F, 0x4C, 0x81)
        h.paragraph_format.space_before = Pt(6)
        h.paragraph_format.space_after = Pt(2)
        return h

    # Section 1
    add_h1("1. Summary of Changes Made in This Session")
    doc.add_paragraph("In this session, the existing Assignment 1 Application Layer dashboard was systematically extended into a dual-panel Transport & Application Layer visualizer:")
    doc.add_paragraph("• Dual-View & Split-View Mode: Extended the right panel to support three distinct views toggled via an interactive tab bar: Transport Layer (L4), Application Layer (L7), and Split View (L7 + L4) displaying both layers simultaneously in lockstep.", style='List Bullet')
    doc.add_paragraph("• Complete RFC 793/9293 Transport Simulation: Added an accurate protocol state engine simulating TCP 3-way handshakes (SYN -> SYN-ACK -> ACK), data segments with flags ([PSH, ACK]), cumulative acknowledgments, and graceful 4-way teardowns ([FIN, ACK]).", style='List Bullet')
    doc.add_paragraph("• Interactive Packet Header & Logic Inspector: Implemented a 32-bit TCP / 8-byte UDP header inspector box displaying RFC bitfield structures (Source/Destination Ports, Seq #, Ack #, Data Offset, Flags, Window Size, Checksum) and plain-English byte-accounting calculations.", style='List Bullet')
    doc.add_paragraph("• Real-Time Connection Telemetry: Added a live telemetry bar displaying Client/Server TCP states (SYN_SENT, ESTABLISHED, FIN_WAIT_1, TIME_WAIT, CLOSED), Congestion Window (cwnd), and Receiver Window (rwnd).", style='List Bullet')
    doc.add_paragraph("• Streaming Protocol Comparison (Extra Credit): Added an interactive toggle between TCP (HLS/DASH) segmented streaming and UDP (Live RTP) datagram delivery to demonstrate reliable byte-stream delivery versus low-latency, connectionless transmission.", style='List Bullet')
    doc.add_paragraph("• Automated Testing & Documentation: Added URL query parameter support (?act=...&step=...&view=...&proto=...) for automated headless browser testing, captured high-resolution screenshots in screenshots/, and generated reflection documents in Markdown, Word, and PDF.", style='List Bullet')

    # Section 2
    add_h1("2. Dual-Panel Synchronization Architecture")
    doc.add_paragraph("The application maintains live synchronization between user-initiated activities (left panel) and the dual visualization tracks (right panel) through a unified event model:")
    doc.add_paragraph("• Hierarchical Event Binding: In script.js, every low-level L4 transport packet (SYN, SYN-ACK, ACK, PSH-ACK, UDP datagram) maintains a direct reference index (l7Index) pointing to its corresponding high-level L7 transaction.", style='List Bullet')
    doc.add_paragraph("• Master Playback Cursor: A single integer cursor tracks playback position across the timeline. All navigation controls (Play/Pause, Step Forward/Back, Replay, and Speed toggles) drive this master cursor, guaranteeing that L4 and L7 views never drift out of sync.", style='List Bullet')
    doc.add_paragraph("• Simultaneous Multi-Track Highlighting: In Split View, as packet i is active on the L4 sequence diagram, transaction pkt[i].l7Index is simultaneously highlighted on the L7 track with a glowing accent border.", style='List Bullet')

    # Section 3
    add_h1("3. What the AI Got Wrong & How It Was Corrected")
    doc.add_paragraph("During development, several protocol inaccuracies common to LLM code generation were identified and corrected to ensure strict RFC compliance:")

    # Table of Errors
    table = doc.add_table(rows=1, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = "Error Category"
    hdr_cells[1].text = "AI Initial Behavior"
    hdr_cells[2].text = "RFC Standard & Applied Correction"
    for cell in hdr_cells:
        for p in cell.paragraphs:
            p.runs[0].font.bold = True
            p.runs[0].font.size = Pt(8.5)
            p.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        set_cell_background(cell, "0F4C81")

    corrections_data = [
        ("SYN & FIN Sequence Space",
         "Treated SYN and FIN flags as consuming 0 sequence bytes because their payload length was 0. This caused the first HTTP GET to reuse the client ISN (Seq=1000).",
         "RFC 793 / 9293 Rule: SYN and FIN control flags consume exactly 1 sequence number space. Corrected: cSeq += 1 immediately after SYN/FIN, ensuring HTTP GET correctly begins at Seq=1001 and peer ACKs 1001."),
        ("Cumulative ACK Calculation",
         "Set ACK equal to the received segment's sequence number (Ack = Seq), confusing acknowledgment with echo.",
         "RFC 9293 Rule: TCP ACK indicates the next expected byte (Ack = Seq + Length). Corrected: 185-byte HTTP GET at Seq 1001 triggers Server Ack = 1001 + 185 = 1186. Pure ACKs (Len=0) do not advance sequence counters."),
        ("Connection Teardown Lifecycle",
         "Generated a simplistic 2-step close (Client FIN -> Server ACK), leaving the server socket unclosed and ignoring state transitions.",
         "RFC Standard 4-Way Teardown: Implemented full bidirectional close: Client FIN, ACK (FIN_WAIT_1) -> Server ACK (FIN_WAIT_2) -> Server FIN, ACK (LAST_ACK / TIME_WAIT) -> Client Final ACK (CLOSED after 2MSL)."),
        ("Streaming Protocol Modeling",
         "Assumed video streaming must be strictly TCP or strictly UDP, missing modern adaptive bitrate practices.",
         "Added Protocol Selector: Implemented dual options (TCP HLS/DASH vs UDP Live RTP) to visually demonstrate reliable byte-stream congestion control vs low-latency datagram delivery.")
    ]

    for err, ai_beh, fix in corrections_data:
        row = table.add_row()
        row.cells[0].text = err
        row.cells[1].text = ai_beh
        row.cells[2].text = fix
        for cell in row.cells:
            for p in cell.paragraphs:
                p.paragraph_format.line_spacing = 1.05
                p.paragraph_format.space_after = Pt(1)
                for r in p.runs:
                    r.font.size = Pt(8)
            set_cell_background(cell, "F9FAFC")

    # Section 4
    add_h1("4. Key Differences Observed Across Transport-Layer Flows")
    doc.add_paragraph("• Web Browsing (HTTP/1.1 over TCP): Characterized by a short-lived request-response lifecycle. Handshake (3 packets) and teardown (4 packets) account for roughly 50% of total packets transferred. Payload is highly asymmetric (small HTTP GET of 185 bytes vs multi-MSS HTML response chunks).", style='List Bullet')
    doc.add_paragraph("• Mail Delivery (SMTP over TCP): Exhibits a conversational, lockstep ping-pong exchange. The server greets first (220 banner), followed by serialized command-reply pairs (EHLO -> 250, MAIL FROM -> 250, RCPT TO -> 250, DATA -> 354, body -> 250, QUIT -> 221). Every step uses the PSH flag to force immediate application delivery, making SMTP highly latency- and RTT-sensitive.", style='List Bullet')
    doc.add_paragraph("• Media Streaming (HLS over TCP vs UDP RTP): TCP streaming demonstrates persistent connection reuse (HTTP Keep-Alive), requesting media segments (seg000.ts, seg001.ts) over an already established socket without repeated handshakes, while ramping Congestion Window (cwnd) via Slow Start (1 -> 2 -> 4 -> 8 -> 16 MSS). Conversely, UDP RTP streaming demonstrates zero-RTT startup, stateless datagrams, 8-byte minimal headers, and zero head-of-line blocking.", style='List Bullet')

    # Section 5
    add_h1("5. Choice of Agentic AI Platform & Model")
    doc.add_paragraph(
        "Google Antigravity with Gemini 3.8 Flash (High Reasoning) was chosen for its direct workspace multi-file editing, "
        "strong RFC finite state machine reasoning, and built-in terminal validation capabilities. It allowed seamless iterative "
        "refinement of sequence logic, UI design, and automated test screenshot generation."
    )

    doc.save("reflection_document.docx")
    print("Successfully generated updated reflection_document.docx")

if __name__ == '__main__':
    create_reflection_docx()
