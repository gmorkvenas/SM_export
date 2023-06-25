#pragma once


#if defined(_WIN32) || defined(_WIN64)
#include <string>
#include <iostream>
#include <sstream>

using namespace std;
#define FM_API extern "C" int _stdcall
#else
#define FM_API extern "C" int
#endif


#define OUT
#define IN




#ifdef __GNUC__
#define PACK( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#endif



enum POS_STATUS {
	POS_STATUS_REGISTRATION_IN_PROGRESS = 1,
	POS_STATUS_REGISTERED = 2,
	POS_STATUS_SUBMITTED_TO_SUSPEND = 3,
	POS_STATUS_SUSPENDED = 4,
	POS_STATUS_SUBMITTED_TO_REGISTER = 5,
	POS_STATUS_SUBMITTED_TO_DEREGISTER = 6,
	POS_STATUS_DEREGISTERED = 7,
	POS_STATUS_CANCELLED = 8
};

///
/// SM preparation order
/// 
/// getSerialNo - get SM unique serial no
/// setSecurityModuleIdentificationNo - value provided by service company
/// setSecurityModuleRegistrationNo - value provided by iEKA
/// generateSMRSAKeyPair - generate RSA key
/// generateSymetricKey - generate both symmetric keys
/// setCertificate - set all certificates. Start from root ones
/// activateSMCertificate



/// <summary>
/// Library init f-ion.
/// </summary>
/// <param name="buff">Returns communication port</param>
/// <param name="aData">Content of sm_lt.ini file. If empty library will search for sm_lt.ini configuration file.</param>
/// <returns>
/// 0 - no error<br>
/// 100 - com port open error
/// </returns>
FM_API initsmlt(OUT char* buff, IN const char* aData);


/// <summary>
/// Frees resources. Call it before unload library.
/// </summary>
/// <returns></returns>
FM_API finishsmlt();


/// <summary>
/// Allows to register document in the security module (SM)
/// </summary>
/// <param name="cashRegisterRegistrationNo">POS unique serial number provided by iEKA.</param>
/// <param name="owner_VAT_ID">Owner TAX payers ID</param>
/// <param name="securityModuleIdentificationNo">Security module identification number provided by service company during SM setup.</param>
/// <param name="documentNo">Document number by provided document type</param>
/// <param name="documentType">
/// 0 - DOC_TYPE_FISCAL<br>
/// 1 - DOC_TYPE_Z<br>
/// 2 - DOC_TYPE_NON_FISCAL 
/// </param>
/// <param name="generalDocumentNo">Document number that counts all types documents</param>
/// <param name="documentDateTime">Document date and time</param>
/// <param name="positiveAmount">Sales transaction amount</param>
/// <param name="VATPositiveAmount">Sales VAT amount</param>
/// <param name="negativeAmount">Procurement amount</param>
/// <param name="docHash">Hash calculated from receipt text. 32 bytes in size provided by caller</param>
/// <param name="certLen">SM certificate serial number length. At least 64 bytes recommended</param>
/// <param name="SMCertificateSerialNr">SM certificate serial number</param>
/// <param name="signature">Infoblock signature. 256 bytes in size provided by caller</param>
/// <param name="infoBlock">Infoblock- encryped document data. 256 bytes in size provided by caller</param>
/// <param name="slipSignature">Slip signature. 16 bytes in size provided by caller</param>
/// <param name="documentCode">Document code to be printed on slip. 16 bytes in size provided by caller</param>
/// <returns></returns>
FM_API signDocument(
	IN char* cashRegisterRegistrationNo,
	unsigned long long int owner_VAT_ID,
	unsigned long securityModuleIdentificationNo,
	unsigned long documentNo,
	unsigned long documentType,
	unsigned long generalDocumentNo,
	unsigned long documentDateTime,
	unsigned long positiveAmount,
	unsigned long VATPositiveAmount,
	unsigned long negativeAmount,
	IN  char* docHash, //32 bytes
	unsigned int* certLen, //at least 64 bytes
	OUT char* SMCertificateSerialNr, //returns certificate of 256 bytes length
	OUT char* signature, //returns signature of 256 bytes length
	OUT char* infoBlock, //returns infoblock of 256 bytes length
	OUT char* slipSignature, //returns slip signature 16 bytes length
	OUT char* documentCode); //returns document code 16 bytes length 


/// <summary>
/// 
/// </summary>
/// <param name="positiveAmount">Sales transaction amount</param>
/// <param name="VATPositiveAmount">Sales VAT amount</param>
/// <param name="negativeAmount">Procurement amount</param>
/// <param name="GTPositiveAmount"></param>
/// <param name="GTVATPositiveAmount"></param>
/// <param name="GTNegativeAmount"></param>
/// <param name="securityModuleRegistrationNo"></param>
/// <param name="availableFiscalDocumentQuantity"></param>
/// <param name="availableNonFiscalDocumentQuantity"></param>
/// <param name="availableZReportDocumentQuantity"></param>
/// <param name="offlineRemainingTime"></param>
/// <returns></returns>
FM_API getStatus(
	unsigned int* positiveAmount,
	unsigned int* VATPositiveAmount,
	unsigned int* negativeAmount,
	unsigned long long* GTPositiveAmount,
	unsigned long long* GTVATPositiveAmount,
	unsigned long long* GTNegativeAmount,
	unsigned int* securityModuleRegistrationNo,
	unsigned int* availableFiscalDocumentQuantity,
	unsigned int* availableNonFiscalDocumentQuantity,
	unsigned int* availableZReportDocumentQuantity,
	unsigned int* offlineRemainingTime);


/// <summary>
/// Sets certificate in SM internal memory
/// </summary>
/// <param name="aCertificateType"><br>
///0 - SM; (SM chain)<br>
///1 - iEka_SM_root; (SM chain)<br>
///2 - partner; (SM chain)<br>
///3 - iEka_data_root; (Data chain)<br>
///4 - iEka_data_sign; (Data chain)<br>
/// </param>
/// <param name="aCertificate">certificate data</param>
/// <param name="aCertificateLength">certificate data length</param>
/// <returns></returns>
FM_API setCertificate(unsigned char aCertificateType, IN unsigned char* aCertificate, unsigned int aCertificateLength);


/// <summary>
/// Retrieves certificate
/// </summary>
/// <param name="aCertificateType"><br>
///0 - SM; (SM chain)<br>
///1 - iEka_SM_root; (SM chain)<br>
///2 - partner; (SM chain)<br>
///3 - iEka_data_root; (Data chain)<br>
///4 - iEka_data_sign; (Data chain)<br>
/// </param>
/// <param name="aCertificate">Certificate data. Caller provides space</param>
/// <param name="aCertificateLength">certificate data length</param>
/// <returns></returns>
FM_API getCertificate(unsigned char aCertificateType, unsigned char* aCertificate, unsigned int* aCertificateLength);


/// <summary>
/// Activates security module certificate after it was uploaded with function setCertificate()
/// </summary>
/// <returns></returns>
FM_API activateSMCertificate();







/// <summary>
/// Retrieves SM serial number provided by producer.
/// </summary>
/// <param name="serial">Serial number. At least 32 bytes in size provided by caller</param>
/// <param name="serial_len">Serial number length.</param>
/// <returns></returns>
FM_API getSerialNo(OUT char* serial, IN OUT unsigned int* serial_len);




/// <summary>
/// Generate RSA key pair
/// </summary>
/// <param name="CSRParamString">Certificate security request parameter<>Example:C=LT,ST=Vilnius,L=Vilnius,O=MY COMPANY,CN=SM-22169803 SM CERT</param>
/// <param name="csr">SM certificate ready to sign with intermediate SM certificate (provided to service comany)<BR>Space provided by caller</param>
/// <param name="csrLen">Space for certificate size</param>
/// <returns></returns>
FM_API generateSMRSAKeyPair(IN char* CSRParamString, OUT unsigned char* csr, IN OUT unsigned int* csrLen);

/// <summary>
/// Generate symmetric key
/// </summary>
/// <param name="keyType">0 - receipt<br>1 - order</param>
/// <param name="encryptedKey">Key encrypted with iEKA public key. Encoded base64. Max length 344 provided by caller</param>
/// <param name="encryptedKeyLength"></param>
/// <param name="keySignature">Signature. Encoded base64. Max length 344 provided by caller</param>
/// <param name="keySignatureLength"></param>
/// <returns></returns>
FM_API generateSymetricKey(unsigned char  keyType, unsigned char* encryptedKey, unsigned int* encryptedKeyLength, unsigned char* keySignature, unsigned int* keySignatureLength);

/// <summary>
/// Get generated symmetric key
/// </summary>
/// <param name="keyType">0 - receipt<br>1 - order</param>
/// <param name="encryptedKey">Key encrypted with iEKA public key. Encoded base64. Max length 344 provided by caller</param>
/// <param name="encryptedKeyLength"></param>
/// <param name="keySignature">Signature. Encoded base64. Max length 344 provided by caller</param>
/// <param name="keySignatureLength"></param>
/// <returns></returns>
FM_API getSymetricKey(IN unsigned char  keyType, OUT unsigned char* encryptedKey, IN OUT unsigned int* encryptedKeyLength, OUT unsigned char* keySignature, IN OUT unsigned int* keySignatureLength);

/// <summary>
/// Retrieves settings cryptogram from SM
/// </summary>
/// <param name="format">0 - DER<br>1 - PEM(Base64 ASCII encoding)</param>
/// <param name="cryptogram">encrypted settings</param>
/// <param name="cryptogramSize">cryptogram size</param>
/// <param name="signature"></param>
/// <param name="signatureSize"></param>
/// <returns></returns>
FM_API getSettingsCrypto(unsigned int format , OUT char* cryptogram, IN OUT unsigned int* cryptogramSize, OUT char* signature, IN OUT unsigned int* signatureSize);


/// <summary>
/// Sets settings cryptogram to SM
/// </summary>
/// <param name="format"></param>
/// <param name="cryptogram">encrypted settings</param>
/// <param name="cryptogramSize">cryptogram size</param>
/// <param name="signature"></param>
/// <param name="signatureSize"></param>
/// <param name="provideSettings">returns true in case of need to provide settings to iEKA</param>
/// <returns></returns>
FM_API setSettingsCrypto(unsigned int format, IN char* cryptogram, unsigned int cryptogramSize, IN char* signature, unsigned int signatureSize, OUT unsigned char* provideSettings);








/// <summary>
/// Retrieves SM certificate serial number
/// </summary>
/// <param name="crtSerialNr">Certificate serial number. Caller provides space. 256 bytes is enough, usually 48.</param>
/// <param name="crtSerialNr_length"></param>
/// <returns></returns>
FM_API getCertificateSerialNo(char* crtSerialNr, unsigned int* crtSerialNr_length);




/// <summary>
/// Provides SM status information retrieved during last any SM command call
/// </summary>
/// <param name="cashRegisterStatus">Cash register state. Values from POS_STATUS enum.</param>
/// <param name="certificateStatus"> Certificate information by bits:<br>
/// iEKA SM root<br>
/// .0 – Will expire soon<br>
/// .1 - Exist<br>
/// .2 - Valid<br>
/// Partner<br>
/// .3 – Will expire soon<br>
/// .4 - Exist<br>
/// .5 - Valid<br>
/// SM<br>
/// .6 – Will expire soon<br>
/// .7 - Exist<br>
/// .8 - Valid<br>
/// iEKA data root<br>
/// .9 – Will expire soon<br>
/// .10 - Exist<br>
/// .11 - Valid<br>
/// iEKA sign<br>
/// .12 – Will expire soon<br>
/// .13 - Exist<br>
/// .14 - Valid<br><br><br>
/// .15 - isActive(1 - active; 0 - inactive)<br>
/// <param name="cashRegisterStatus"></param>
/// <param name="certificateStatus"></param>
/// <param name="generalDocumentNo">Document number that counts all types documents</param>
/// <param name="FDocumentNo">Fiscal document counter</param>
/// <param name="NFDocumentNo">Non fiscal document counter</param>
/// <param name="ZNumber">Z report counter</param>
/// <param name="securityModuleSoftwareVersionID"></param>
/// <returns></returns>
FM_API getLastStatus(
	unsigned char * cashRegisterStatus,
	unsigned long* certificateStatus,
	unsigned long* generalDocumentNo,
	unsigned long* FDocumentNo,
	unsigned long* NFDocumentNo,
	unsigned long* ZNumber,
	unsigned long* securityModuleSoftwareVersionID);



/// <summary>
/// Set SM registration number provided by iEKA
/// </summary>
/// <param name="value"></param>
/// <returns></returns>
FM_API setSecurityModuleRegistrationNo(unsigned int value);

/// <summary>
/// Get SM registration number provided by iEKA
/// </summary>
/// <param name="value"></param>
/// <returns></returns>
FM_API getSecurityModuleRegistrationNo(unsigned int* value);

/// <summary>
/// Set SM identification number provided by service company
/// </summary>
/// <param name="value"></param>
/// <returns></returns>
FM_API setSecurityModuleIdentificationNo(char* value);

/// <summary>
/// Get SM identification number provided by service company
/// </summary>
/// <param name="value"></param>
/// <param name="valueLength"></param>
/// <returns></returns>
FM_API getSecurityModuleIdentificationNo(char* value, unsigned int* valueLength);

/// <summary>
/// Sets owner code
/// </summary>
/// <param name="value"></param>
/// <returns></returns>
FM_API setOwnerCode(unsigned long long value);

/// <summary>
/// Gets owner code
/// </summary>
/// <param name="value"></param>
/// <returns></returns>
FM_API getOwnerCode(unsigned long long* value);

/// <summary>
/// Set VAT ID
/// </summary>
/// <param name="value"></param>
/// <returns></returns>
FM_API setVAT_ID(unsigned long long int value);

/// <summary>
/// Get VAT ID
/// </summary>
/// <param name="value"></param>
/// <returns></returns>
FM_API getVAT_ID(unsigned long long int* value);

/// <summary>
/// Set cash register (POS) registration number
/// </summary>
/// <param name="value"></param>
/// <returns></returns>
FM_API setCashRegisterRegistrationNo(char* value);

/// <summary>
/// Get cash register (POS) registration number
/// </summary>
/// <param name="value"></param>
/// <param name="valueLength"></param>
/// <returns></returns>
FM_API getCashRegisterRegistrationNo(char* value, unsigned int* valueLength);


/***************************/

FM_API getParamStr(unsigned int paramId, char* value, unsigned int* valueLength);
FM_API getParamInt32(unsigned int paramId, unsigned int* value);
FM_API getParamInt64(unsigned int paramId, unsigned long long int* value);
FM_API getErrorFriendlyText(int err, char* errDescr, int* insize);

FM_API sendOnlyInternal(int expected_time, char* poutBuf, char* pinBuf, unsigned int* outsize, unsigned int* insize, int aifunctionChoices);
FM_API repeatLastAnswer();
//TODO  pasitarti
FM_API getErrorByCode(int aError, char* description, int* aLen);
FM_API fninfosm_lt(int atype, char* info, unsigned int* n);
int sendOnlyA(int expected_time, char cmd);
FM_API execDebugCommand(unsigned int aparam, char* fromSMBuff, int* fromSMBuff_length);
FM_API logHandlingsmlt();
