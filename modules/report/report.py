from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import cm
import pyshark
from time import localtime, strftime
import os

class report():
    '''
    Class to create pdf reports as an result dokumentation of the Fuzzing-Test
    '''
    def __init__(self, export_path = None):
        '''
        Konstrutor
        export_path = Optinal path where to save the report. If no path is set
        save to excecution directory
        '''
        stime = strftime("%Y-%m-%d_%H:%M:%S", localtime())
        if export_path is None:
            self.c = canvas.Canvas("Fuzzing_report_{}.pdf".format(stime), pagesize=letter)
        else:
            self.c = canvas.Canvas(export_path + "/Fuzzing_Report_{}.pdf".format(stime), pagesize=letter)

    def print_singel_test_summary(self,count,file,conection,payload=None):
        '''
        Single page of one Test that is excecutet with multiple mutations
        count = count of Mutations
        file = the referenzfile as an input
        conection = string is the connection keep open till the end of the test
        payload = the payload that might be coling the connection
                (the last mms packet that was send bevor the connection cloased)
        '''
        self.c.setFont("Helvetica", 20)
        self.c.drawString(4*cm, 25*cm, "Gesamte Anzahl von Tests:   {}".format(count))
        self.c.setFont("Helvetica", 16)
        if (len(file)>35):
            file = file[:32]
            file = file + '...'
        self.c.drawString(2.5*cm, 23*cm, "Getestetes Referenzfile:  {}".format(file))
        self.c.setFont("Helvetica", 10)
        self.c.drawString(2.5*cm, 21*cm, "Verbindung bei dem Test aufrechterhalten:  {}".format(conection))
        if not payload is None:
            self.c.setFillColorRGB(0.8, 0.06, 0.03)
            self.c.drawString(2.5*cm, 20*cm, "Error Payload near:")
            chunks, chunk_size = len(payload), 30
            for i, chung in enumerate([ payload[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]):
                self.c.drawString(2.5*cm, (19-i)*cm, '{}'.format(chung))
        self.c.showPage()


    def print_global_summary(self,count,files):
        '''
        Singel page of a global summary
        count = the maximal number of Tests
        files = directory of all refrenece test that are the input to the Fuzzing_Report_
        '''
        self.c.setFont("Helvetica", 20)
        self.c.drawString(4*cm, 25*cm, "Gesamte Anzahl von Tests:   {}".format(count))
        self.c.setFont("Helvetica", 16)
        self.c.drawString(2.5*cm, 23*cm, "Getestete Referenzfiles:")
        self.c.setFont("Helvetica", 10)
        self.c.drawString(2.5*cm, 22*cm, "XX_01 = Singe Write")
        self.c.drawString(2.5*cm, 21.5*cm, "XX_12 = sbo-with-normal-security")
        self.c.drawString(2.5*cm, 21*cm, "XX_14 = sbo-with-enhanced-security")
        self.c.drawString(9*cm, 22*cm, "XX_11 = direct-with-normal-security")
        self.c.drawString(9*cm, 21.5*cm, "XX_13 = direct-with-enhanced-security")
        self.c.drawString(9*cm, 21*cm, "XX_20 = SGCB")
        self.c.setFont("Helvetica", 9)
        for i, tfile in enumerate(files, 1):
            if i % 38 == 0:
                self.c.showPage()
            self.c.drawString(2.5*cm, (20-((i%38)*0.5))*cm, str(tfile))
        self.c.showPage()

    def print_cover(self):
        '''
        Singe PDF page that is the cover of every test
        '''
        #c.drawString(20,450,s)
        self.c.setFont("Helvetica", 28)
        self.c.drawString(9*cm, 25*cm, "Report")
        self.c.setFont("Helvetica", 12)
        self.c.drawString(6*cm, 23*cm, "Report generated with IEC61850 fuzzy testing tool.")
        self.c.drawString(7*cm, 22*cm, "(Copyright 2018 by Lars Lengersdorf)")
        self.c.setFont("Helvetica", 16)
        self.c.drawString(4*cm, 18*cm, "Testdatum:   {}".format(strftime("%Y-%m-%d_%H:%M:%S", localtime())))
        self.c.showPage()

    def print_package(self,package, filename):
        '''
        Singel PDF page that use the string from pyshark print to comand line
        function to show the structure of the entire package
        package = string from pyshark
        filename = Filename of the pcap data
        '''
        self.c.setFont("Helvetica", 16)
        if (len(filename)>45):
            filename = filename[:42]
            filename = filename + '...'
        self.c.drawString(2.5*cm, 25*cm, "File:   {}".format(filename))
        self.c.drawString(2.5*cm, 24*cm, "Paketaufbau Referenz-Paket:")
        s = str(package).split('Layer TPKT:')
        bistcp = s[0]
        vontcp = 'Layer TPKT:' + s[1]
        s = str(bistcp)

        textobject = self.c.beginText()
        textobject.setFont("Helvetica", 8)
        textobject.setTextOrigin(2.5*cm, 23*cm)
        news = str()
        for line in s.splitlines():
            line = line.replace("\t", "")
            if len(line) > 70:
                line = line [:67]
                line = line + '...'
            if line.startswith('Layer'):
                textobject.setFillColorRGB(0.01, 0.3, 0.74)
                textobject.textLine(line)
                textobject.setFillColorRGB(0,0,0)
            else:
                textobject.textLine(line)
        textobject.setTextOrigin(13.5*cm, 23*cm)
        s = str(vontcp)
        for line in s.splitlines():
            line = line.replace("\t", "")
            if len(line) > 75:
                line = line [:73]
                line = line + '...'
            if line.startswith('Layer'):
                textobject.setFillColorRGB(0.01, 0.3, 0.74)
                textobject.textLine(line)
                textobject.setFillColorRGB(0,0,0)
            else:
                textobject.textLine(line)
        self.c.drawText(textobject)
        self.c.showPage()


    def save_report(self):
        '''
        save multi page report to pdf
        '''
        self.c.save()
