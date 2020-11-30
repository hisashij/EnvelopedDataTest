/*****************************
* EnvelopedDataTest.c
* It is a command line tool which encodes PKCS#7 enveloped data
* from the source file and the recepient certificate (X.509 DER format).
* 
* Usage: EnvelopedDataTest <source file> <enveloped data file> <recipient cert>
* 
* The wolfSSL static library is needed to be linked.
*****************************/

#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include "wolfssl/wolfcrypt/pkcs7.h"

/**********************************************
* Name:     mallocAndLoadFile
* Function: Allocate memory and load binary file.
* Return:   Loaded data length.
**********************************************/
static int mallocAndLoadFile(const char *pFileName, byte** ppData)
{
    struct stat statBuf;
    FILE* pFile = NULL;
    int iDataLen = 0;
    
    /* Obtain file size */
    if (0 != stat(pFileName, &statBuf)) {
        fprintf(stderr, "%s: Cannot be obtain its file size.\n", pFileName);
        return -1;
    }
    iDataLen = statBuf.st_size;

    /* Allocate memory */
    if (!(*ppData = malloc(iDataLen))) {
        fprintf(stderr, "Memory allocation error.\n");
        return -1;
    }

    /* Open file */
    fopen_s(&pFile, pFileName, "rb");
    if (!pFile) {
        fprintf(stderr, "%s: Cannot be opened.\n", pFileName);
        free(*ppData);
        return -1;
    }

    /* Load file data */
    if (iDataLen != fread(*ppData, 1, iDataLen, pFile)) {
        fprintf(stderr, "%s: Cannot be loaded.\n", pFileName);
        free(*ppData);
        fclose(pFile);
        return -1;
    }
    fclose(pFile);

    return iDataLen;
}

/**********************************************
* Name:     writeFile
* Function: Open file and write binary data.
* Return:   Written data length
**********************************************/
static int writeFile(const char* pFileName, char* pData, int iDataLen)
{
    FILE* pFile = NULL;

    /* Open file */
    fopen_s(&pFile, pFileName, "wb");
    if (!pFile) {
        fprintf(stderr, "%s: Cannot be opened.\n", pFileName);
        return -1;
    }

    /* Write data to file */
    if (iDataLen != fwrite(pData, 1, iDataLen, pFile)) {
        fprintf(stderr, "%s: Cannot be written.\n", pFileName);
        fclose(pFile);
        return -1;
    }
    fclose(pFile);

    return iDataLen;
}

/**********************************************
* Name:     mallocAndEncodeEnvelopedData
* Function: Allocate memory and encode EnvelopedData.
* Return:   Loaded data length.
**********************************************/
static int mallocAndEncodeEnvelopedData(
    const byte* pSourceData,
    const int iSourceLen,
    const byte* pCertData,
    const int iCertLen,
    byte** ppEnvelopedData)
{
    int    iRet;
    PKCS7* pPkcs7;
    RNG    rng;
    int iEnvelopedDataBuffer;

    /* Initialize randome number */
    if (0 != (iRet = wc_InitRng(&rng))) {
        fprintf(stderr, "wc_InitRng() failed, ret = %d\n", iRet);
        return -1;
    }

    /* Create PKCS7 object */
    if (!(pPkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID))) {
        fprintf(stderr, "wc_PKCS7_New() failed\n");
        return -1;
    }

    pPkcs7->rng = &rng;
    pPkcs7->content = (byte*)pSourceData;
    pPkcs7->contentSz = iSourceLen;
    pPkcs7->contentOID = DATA;
    pPkcs7->encryptOID = AES256CBCb;

    /* Add recipient using RSA certificate (KTRI type) */
    if (0 > (iRet = wc_PKCS7_AddRecipient_KTRI(pPkcs7, pCertData, iCertLen, 0))) {
        fprintf(stderr, "wc_PKCS7_AddRecipient_KTRI() failed, ret = %d\n", iRet);
        wc_PKCS7_Free(pPkcs7);
        return -1;
    }

    /* Allocate memory for EnvelopedData */
    iEnvelopedDataBuffer = iSourceLen + 1024;
    if (!(*ppEnvelopedData = malloc(iEnvelopedDataBuffer))) {
        fprintf(stderr, "Memory allocation error.\n");
        wc_PKCS7_Free(pPkcs7);
        return -1;
    }

    /* Encode EnvelopedData, returns size */
    if (0 >= (iRet = wc_PKCS7_EncodeEnvelopedData(pPkcs7, *ppEnvelopedData, iEnvelopedDataBuffer))) {
        fprintf(stderr, "wc_PKCS7_EncodeEnvelopedData() failed, ret = %d\n", iRet);
        free(*ppEnvelopedData);
        wc_PKCS7_Free(pPkcs7);
        return -1;

    }
    wc_PKCS7_Free(pPkcs7);

    return iRet;
}

/**********************************************
* Main Function
**********************************************/
int main(int argc, char **argv)
{
    /* Variable Declaration */
    char* pSourceFileName = NULL;
    byte* pSourceData = NULL;
    int iSourceLen = 0;
    char* pEnvelopedFileName = NULL;
    byte* pEnvelopedData = NULL;
    int iEncodedLen = 0;
    char* pCertFileName = NULL;
    byte* pCertData = NULL;
    int iCertLen = 0;

    /* Command line variable check */
    if (3 >= argc) {
        fprintf(stdout, "Usage: %s <source file> <enveloped data file> <recipient cert>\n", argv[0]);
        return -1;
    }
    pSourceFileName = argv[1];
    pEnvelopedFileName = argv[2];
    pCertFileName = argv[3];

    /* Load Source File */
    if (0 > (iSourceLen = mallocAndLoadFile(pSourceFileName, &pSourceData))) {
        return -1;
    }

    /* Load Cert File */
    if (0 > (iCertLen = mallocAndLoadFile(pCertFileName, &pCertData))) {
        free(pSourceData);
        return -1;
    }
   
    /* Encode enveloped data */
    if (0 > (iEncodedLen = mallocAndEncodeEnvelopedData(pSourceData, iSourceLen, pCertData, iCertLen, &pEnvelopedData))) {
        free(pSourceData);
        free(pCertData);
        return -1;
    }

    /* Write enveloped data to file */
    if (0 > writeFile(pEnvelopedFileName, pEnvelopedData, iEncodedLen)) {
        free(pSourceData);
        free(pCertData);
        free(pEnvelopedData);
        return -1;
    }

    free(pSourceData);
    free(pCertData);
    free(pEnvelopedData);
    return 0;
}