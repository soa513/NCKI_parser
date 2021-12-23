import os, sys, re
import pdfminer.high_level

#Paths
export_file_path = './export.json'	 #directory where exported data will be saved
pdf_dir = './samples/' #directory with pdfs


def list_to_string(input_string):  #convert list to one string
	out_string = ""
	for elem in input_string.splitlines():
		if out_string == "":
			out_string = elem
		else:
			out_string = out_string.strip() + " " + elem
	return(out_string)

def parse_one_vuln_pdf(text_from_pdf):  #parse pdf with one vulnarability

	#making points in text by searching predefined text
	available_updates_point = text_from_pdf.find('Наличие обновления')
	vuln_id_point = text_from_pdf.find('Идентификатор уязвимости')
	program_error_id_point = text_from_pdf.find('Идентификатор программной ошибки ')
	vuln_detail_point = text_from_pdf.find('Описание уязвимости')
	vuln_products_point = text_from_pdf.rfind('Уязвимый продукт ')
	recommendations_for_elimination_point = text_from_pdf.rfind('Рекомендации по устранению')
	vuln_severity_assessment_point = text_from_pdf.rfind('Оценка критичности уязвимости')
	attack_vector_point = text_from_pdf.rfind('Вектор атаки')

	# all text from first_point to first_point + point_to_end_of_string, than strip and to single string
	available_updates = list_to_string(text_from_pdf[available_updates_point:available_updates_point+text_from_pdf[available_updates_point:].find("\n")].strip())
	vuln_name = list_to_string(text_from_pdf[available_updates_point+text_from_pdf[available_updates_point:].find("\n"):vuln_id_point].strip())
	vuln_id = list_to_string(text_from_pdf[vuln_id_point+text_from_pdf[vuln_id_point:].find("\n"):program_error_id_point].strip())
	program_error_id = list_to_string(text_from_pdf[program_error_id_point+text_from_pdf[program_error_id_point:].find("\n"):vuln_detail_point].strip())
	vuln_products = list_to_string(text_from_pdf[vuln_products_point+text_from_pdf[vuln_products_point:].find("\n"):recommendations_for_elimination_point].strip())
	vuln_severity_assessment = list_to_string(text_from_pdf[vuln_severity_assessment_point:vuln_severity_assessment_point+text_from_pdf[vuln_severity_assessment_point:].find("\n")].strip())

	# making json-like string
	json_string = '{vuln_name:[' + vuln_name +']; vuln_products:[' + vuln_products + ']; available_updates:[' + available_updates \
					+ ']; vuln_id:[' + vuln_id + ']; program_error_id:[' + program_error_id + ']; vuln_severity_assessment:[' + vuln_severity_assessment + ']}'
	# return resuls
	return(json_string)

def parse_many_vuln_pdf(text_from_pdf):
	#making points in text by searching predefined text
	available_updates_point = text_from_pdf.find('Наличие обновления')
	vuln_name_point = text_from_pdf.find('Множественные уязвимости ')
	vuln_products_point = text_from_pdf.rfind('Уязвимый продукт ')
	vuln_date_point = text_from_pdf.find('Дата выявления')

	# all text from first_point to first_point + point_to_end_of_string, than strip and to single string
	available_updates = list_to_string(text_from_pdf[available_updates_point:available_updates_point+text_from_pdf[available_updates_point:].find("\n")].strip())
	vuln_name = list_to_string(text_from_pdf[vuln_name_point:vuln_name_point+text_from_pdf[vuln_name_point:].find("\n")].strip())
	vuln_products = list_to_string(text_from_pdf[vuln_products_point+text_from_pdf[vuln_products_point:].find("\n"):vuln_date_point].strip())
	
	#for multiple values
	vuln_ids = ''
	for vuln_id_point in re.finditer('CVE', text_from_pdf):  #search all indexes with "CVE"
		#text from start index to end of string
		vuln_id = text_from_pdf[vuln_id_point.start():vuln_id_point.start()+text_from_pdf[vuln_id_point.start():].find("\n")].strip()
		#fill vuln_ids var
		if vuln_ids == '':
			vuln_ids = vuln_id + '; '
		else: 
			vuln_ids = vuln_ids + vuln_id +'; '

	vuln_severity_assessments = ''
	for vuln_severity_assessment_point in re.finditer('CVSS', text_from_pdf):
		vuln_severity_assessment = text_from_pdf[vuln_severity_assessment_point.start():vuln_severity_assessment_point.start()+text_from_pdf[vuln_severity_assessment_point.start():].find("\n")].strip()
		if vuln_severity_assessments == '':
			vuln_severity_assessments = vuln_severity_assessment.strip() + '; '
		else: 
			vuln_severity_assessments = vuln_severity_assessments + vuln_severity_assessment.strip() +'; '

	program_error_ids = ''
	for program_error_id_point in re.finditer('CWE', text_from_pdf):
		program_error_id = text_from_pdf[program_error_id_point.start():program_error_id_point.start()+text_from_pdf[program_error_id_point.start():].find("\n")].strip()
		if program_error_ids == '':
			program_error_ids = program_error_id.strip() + '; '
		else: 
			program_error_ids = program_error_ids + program_error_id.strip() +'; '

	# making json-like string
	json_string = '{vuln_name:[' + vuln_name +']; vuln_products:[' + vuln_products + ']; available_updates:[' + available_updates \
					+ ']; vuln_ids:[' + vuln_ids + ']; program_error_ids:[' + program_error_ids + ']; vuln_severity_assessments:[' + vuln_severity_assessments + ']}'
	# return resuls
	return(json_string)

errors = []
export_file = open(export_file_path, 'w')	#open file to write exported data
for filename in os.listdir(pdf_dir):		#list all files in pdf_dir
	path_string = pdf_dir + filename
	try:									#checker for pdfminer and its errors
		with open(path_string, 'rb') as file:
  			text_from_pdf = pdfminer.high_level.extract_text(file).strip() #read file with pdfminer
		file.close()

		if text_from_pdf.find('УВЕДОМЛЕНИЕ ОБ УЯ3ВИМОСТИ') > 0: 	#checking that file contain only one vulnarability details
			json_string = parse_one_vuln_pdf(text_from_pdf)			#run function for on vulnerability pdf
		elif text_from_pdf.find('УВЕДОМЛЕНИЕ ОБ УЯ3ВИМОСТЯХ') > 0:	#checking that file contain more that one vulnerabilities details
			json_string = parse_many_vuln_pdf(text_from_pdf)		#run function for many vulnerabilities pdf
		else:
			error_string = "File content error, can't find text like 'УВЕДОМЛЕНИЕ ОБ УЯ3ВИМОСТ'' fileneme: " +filename # can't find predifined text in parsed pdf
			errors.append(error_string)							#collect errors
		out_string = '[' + filename + ',' + json_string + ']\n' #making final json-like output string
		export_file.write(out_string)							#write final string to file
	except:
		error_string = "Can't parse file: " + filename			#Any pdfminer error
		errors.append(error_string)								#collect errors
export_file.close()
print(errors)


