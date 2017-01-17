function New-X509Certificate 
{ 
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$CommonName,
        [Parameter(Mandatory=$true)]
        [ValidateSet("1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2")]
        [ValidateNotNullOrEmpty()]
        [String]$EKValue
    )      

###############INITIALIZE THE DESIRED SUBJECT NAME IN THE CERTIFICATE######################################
    $DN = New-Object -ComObject 'X509Enrollment.CX500DistinguishedName.1'
    <##
    >The 'Encode' method initializes the object from a string that contains a distinguished name.
    >First param: A basic String (BSTR) variable that contains the string to encode
    >Second param: An X500NameFlags enumeration value that specifies the format of the 
    >encoded value.X509Enrollment.CX500DistinguishedName exposes all the various encoding options available

        - XCN_CERT_NAME_STR_NONE = 0
            +Display characteristics are not identified
    >If the function succeeds, the function returns S_OK
    ##>
    $DN.Encode("CN=$CommonName", 0)  

###############CREATES THE SUBJECT'S PRIVATE KEY############################################################
    <##
    The IX509PrivateKey interface represents an asymmetric private key that can be used for encryption,
    signing and key agreement.

    ##>
    $PrivateKey = New-Object -ComObject 'X509Enrollment.CX509PrivateKey.1'
    $PrivateKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider" #Cryptographic provider
    
    <##
    >KeySpec = Specifies whether a PK can be used for (signing or Encryption or both)
        - XCN_AT_NONE = 0
            +It is set if the provider that supports the key is a Cryptography API: Next Generation (CNG)
        -XCN_AT_KEYEXCHANGE = 1
            +The Key can be used to encrypt (including Key Exchange) or sign depending on the Algorithm.
            +For RSA Algorithms, if this value is set, the Key can be used for both signing and Encryption
            +For other Alrgorithms, signing may not be supported.
        -XCN_AT_SIGNATURE = 2
            +The key can be used for signing 
    ##>
    $PrivateKey.KeySpec = 1 #XCN_AT_KEYEXCHANGE
    
    <##
    >The 'ExportPolicy' property specifies or retrieves export constraints for a private key
    >This property is web enabled for both input and output
    >The property is read and Write

        -X509PrivateKeyExportFlags values to specify the export policy for private Key
            +XCN_NCRYPT_ALLOW_EXPORT_NONE = 0 /Export is not allowed. This is the default value
            +XCN_NCRYPT_ALLOW_EXPORT_FLAG = 1 /The private key can be exported
            +XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG = 2 /The private key can be exported in plain text
            +XCN_NCRYPT_ALLOW_ARCHIVING_FLAG = 4 /The private key can be exported once for archiving
            +XCN_NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG = 8 /Private key can be exported once in plain Text for archiving
    
    ##>
    $PrivateKey.ExportPolicy = 2 # XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
    
    <##
    >The Machine Context property specifies or retrieves a Boolean value (true or false) that identifies
    the local certificate store context.This property is web enabled for both input and output
    >A VARIANT_BOOL variable that identifies the certificate store context
        - $TRUE = for the computer
        - $FALSE = for the user
    ##>
    $PrivateKey.MachineContext = $true
    
    $PrivateKey.Length = 2048 #Specifies or retrieves the length, in bits, of the private key
    $PrivateKey.Create() #The create method creats an asymmetric Private Key

###############USE THE IOBJECTID INTERFACE which REPRESENTS AN OBJECT IDENTIFIER(OID)##############################
    $HashAlg = New-Object -ComObject 'X509Enrollment.CObjectId.1'
    
    <##
    >The InitializeFromAlgorithmName method initializes the object from an algorithm or an object identifier.

        -ObjectIDGroupId = Specifies the OID Group to search
            +XCN_CRYPT_ANY_GROUP_ID = 0
            +XCN_CRYPT_HASH_ALG_OID_GROUP_ID       = 1,
            +XCN_CRYPT_ENCRYPT_ALG_OID_GROUP_ID    = 2,
            +XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID     = 3,
            +XCN_CRYPT_SIGN_ALG_OID_GROUP_ID       = 4,
            +XCN_CRYPT_RDN_ATTR_OID_GROUP_ID       = 5,
            +XCN_CRYPT_EXT_OR_ATTR_OID_GROUP_ID    = 6,
            +XCN_CRYPT_ENHKEY_USAGE_OID_GROUP_ID   = 7,
            +XCN_CRYPT_POLICY_OID_GROUP_ID         = 8,
            +XCN_CRYPT_TEMPLATE_OID_GROUP_ID       = 9,
            +XCN_CRYPT_LAST_OID_GROUP_ID           = 9,
            +XCN_CRYPT_FIRST_ALG_OID_GROUP_ID      = 1,
            +XCN_CRYPT_LAST_ALG_OID_GROUP_ID       = 4,
            +XCN_CRYPT_OID_DISABLE_SEARCH_DS_FLAG  = 0x80000000,
            +XCN_CRYPT_KEY_LENGTH_MASK             = 0xffff0000

        -ObjectIdPublicKeyFlags = Enumeration value that specifies whether to search for signing or an encryptionalgorithm
            +XCN_CRYPT_OID_INFO_PUBKEY_ANY               = 0, /Agorithm can be used for signing or encryption
            +XCN_CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG     = 0x80000000, /Algorithm used for signing
            +XCN_CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG  = 0x40000000 /Algorithm is used for encryption
        
        -AlgorithmFlags = Enumeration values to redefine the search for a cryptographic algorithm
            +AlgorithmFlagsNone  = 0x00000000, /no flags are specified
            +AlgorithmFlagsWrap  = 0x00000001 /Algorithm is used for key wrapping.
       
        -strAlgorithName = a BSTR variable that contains the name. CNG Algorithm Names
            + 'SHA512' = the 512-bit secure hash algorithm
    ##>
    $HashAlg.InitializeFromAlgorithmName(1, 0, 0, 'SHA512')

    <##
    >InitializeMethodFromValue method initializes the object from a string that contains a dotted decimal OID
    >1.3.6.1.5.5.7.3.1 = Indicates that the certificate can be used as an SSL Server Certificate
    >1.3.6.1.5.5.7.3.2 = Indicates that the certificate can be used as an SSL Client Certificate
    >All Certificate content is encoded using Abstract Syntax Notation 1 Distinguished Encoding Rules (ASN.1.DER)
    >$ServerAuthoid stores the ODI value which will be encoded later
    ##>
    $ServerAuthOid = New-Object -ComObject 'X509Enrollment.CObjectId.1'
    $ServerAuthOid.InitializeFromValue($EKValue)
    
    <##
    >X509Enrollment.CObjectIds.1 allows you to deine methods and properties that enable you to manage a
     collection of IObjectID Objects
    >X509Enrollment.CX509ExtensionEnhancedKeyUsage.1 used to define a collection of OIDs that identify the
     intended uses of the public key contained in the certificate.
    >The InitializeEncode method enables you to construct a Distinguished Encoding Rules 
     (DER) encoded Abstract Syntax Notation One (ASN.1) extension object from raw data (
    >InitializeEncode initializes the extension from a collection of OIDs that specify the intended uses
     of the public Key
    ##>
    $EkuOid = New-Object -ComObject 'X509Enrollment.CObjectIds.1'
    $EkuOid.Add($ServerAuthOid) #Points to the ObjectId value set before by $serverAuthoid
    $EkuExtension = New-Object -ComObject 'X509Enrollment.CX509ExtensionEnhancedKeyUsage.1'
    $EkuExtension.InitializeEncode($EkuOid) #

################SIGN AND ENCODE A CERTIFICATE#####################################################################
    <##
    >The IX509CertificateRequestCertificate interface represents a request object for a self-generated
     certificate, enabling you to create a certificate directly without going through a registration or 
     certification authority.

        -InitializeFromPrivateKey = Initializes the certificate request using the $privatekey already
         created before. It uses an IX509PriavteKey object and optionally a template.
            +X509CertificateEnrollmentContext = Enumeration value requested
                *ContextUser=0x1, /The certificate is being requested for an end user
                *ContextMachine=0x2, /The certificate is intended for a computer.
                *ContextAdministratorForceMachine=0x3 /The certificate is being requested by an administrator acting on the behalf of a computer.
            +PrivateKey = Pointer to the IX509PrivateKey interface that represents the private key = $PrivateKey
            +TemplateName = a BSTR variable that contains the Common Name (CN) of the template as it appears
             in active direcoty or the dotted decimal object identifier.

        -  X509Extensions = Interface that defines methods and properties to manage a collection of IX509 extensions
            +Add = Adds an IX509Extension object to the collection = $EKUExtension
        -  Hashalgorithm = Specifies and retrieves the OID of the hash algorithm used to sign the cert request
        -  Encode = Signs and encodes a Certificate request and creates a key pair if one does not exist.
             The request is encoded by using Distinguished Encoding Rules (DER) as defined by the ASN.1
             The encoding process creates a byte array.

    >For a PKCS #10 request, this method:
        -Updates the private key or creates the key if necessary.
        -Populates the public key from the private key.
        -Updates the extensions, adding any default extensions and taking account of the suppressed
         OID collection and critical extension OID collection.
        -Updates the attributes, adding default attributes and taking account of the suppressed OID collection.
        -Assembles and encodes the unsigned updated request.
        -Creates and encodes a signature.
        -Encodes the signature and the unsigned request.
    ##>
    $Certificate = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestCertificate.1'
    $Certificate.InitializeFromPrivateKey(2, $PrivateKey, '')
    $Certificate.Subject = $DN
    $Certificate.Issuer = $Certificate.Subject
    $Certificate.NotBefore = [DateTime]::Now.AddDays(-1)
    $Certificate.NotAfter = $Certificate.NotBefore.AddDays(90)
    $Certificate.X509Extensions.Add($EkuExtension)
    $Certificate.HashAlgorithm = $HashAlg
    $Certificate.Encode()

################ENROLL IN A CERTIFICATE HIERARCHY AND INSTALL A CERTIFICATE RESPONSE############################
    <##
    >The IX509Enrollment interface represents the top level object and enables you to enroll in a cert and
     install a certificate response.

        -CreateRequest()
         This method calls the Encode Method to encode the raw data from the associated request object
         It uses the information provided during initialization and other properties that have been specified
         Creates a dummy certificate and places it in the request store.
         Before calling this method, one must initialize the IX509Enrollment object (Initializefromrequest)
            +EncodingTye = Enumeration value that specifies the type of unicode encoding applied to the
             DER-encoded request. The default value is XCN_CRYPT_STRING_BASE64
                *XCN_CRYPT_STRING_BASE64HEADER         = 0,
                *XCN_CRYPT_STRING_BASE64               = 0x1,
                *XCN_CRYPT_STRING_BINARY               = 0x2,
                *XCN_CRYPT_STRING_BASE64REQUESTHEADER  = 0x3,
                *XCN_CRYPT_STRING_HEX                  = 0x4,
                *XCN_CRYPT_STRING_HEXASCII             = 0x5,
                *XCN_CRYPT_STRING_BASE64_ANY           = 0x6,
                *XCN_CRYPT_STRING_ANY                  = 0x7,
                *XCN_CRYPT_STRING_HEX_ANY              = 0x8,
                *XCN_CRYPT_STRING_BASE64X509CRLHEADER  = 0x9,
                *XCN_CRYPT_STRING_HEXADDR              = 0xa,
                *XCN_CRYPT_STRING_HEXASCIIADDR         = 0xb,
                *XCN_CRYPT_STRING_HEXRAW               = 0xc,
                *XCN_CRYPT_STRING_NOCRLF               = 0x40000000,
                *XCN_CRYPT_STRING_NOCR                 = 0x80000000
            +pValue = Pointer to a BSTR variable that contains the DER-encoded request.
             In this case in powershell, we are using the $Enroll variable with contains the DER enconded request
             It is already being used since it is calling the CreateRequest method

        -InstallResponse()
         Installs a certificate chain on the end-entity computer.
            +Restrictions (enumeration value)
            Specifies the type of certificate that can be installed.
                *AllowNone                  = 0x00000000, /Does not allow the installation of untrusted certificates or certificates for which there is no corresponding request.
                *AllowNoOutstandingRequest  = 0x00000001, /Creates the private key from the certificate response rather than from the dummy certificate
                 This makes the dummy certificate options. If this value is not set, the dummy certificate must exist and the private key is extracted from it.
                *AllowUntrustedCertificate  = 0x00000002, /Installs untrusted end entity and certification authority certificates.
                 CA certificates include root and subordinate certification authority certificates.
                 Entity certificates are installed to the personal store, and certification authority certificates are installed to the certification store. 
                *AllowUntrustedRoot         = 0x00000004 / Performs the same action as the AllowUntrustedCertificate flag but also install the certificate even if the
                 certificate chain cannot be built because the root is not trusted.
            +Response = A BSTR variable that contains the DER-Encoded response
             in this case is the $CSR since the request started with $Enroll back in CreateRequest().
             Remember in here we are using the DER-encoded Response and not the request.
            +Encoding = An EncodingType Enumeration value that specifies the type of encoding applied to the string.
             EncodingTpe was shown above and in this case, the script is choosing Enumeration Value 1 since it was encoded by the type of unicode encoding Base64
            +Password = Optional password for the Certificate installation. This can be NULL or an empy string
             It there is a password, clear it from memory when you have finished.

        -CreatePFX
         This method creates a Personal Information Exchange(PFX) message.
         The message is contained in a byte array that is encoded by using DER as defined by ASN.1 standard
         The DER-encoded byte array is represented by a string that is either a pure binary sequence or is Unicode encoded.
            +Password = A BSTR variable that contains a password for the PFX Message.
             This can be NULL to indicate that no password is isued.
            +ExportOptions = Expects an Enumeration Value that specifies how much of the certificate chain is exported.
             You can export the certificate only, the certificate chain without the root, or the entire chain.
                *PFXExportEEOnly         = 0, / includes only the end entity certificate
                *PFXExportChainNoRoot    = 1, / Includes the certificate chain without the root CA certificate
                *PFXExportChainWithRoot  = 2 /Includes the entire certificate chain.
            +Encoding = expects an enumeration value. By default this is XCN_CRYPT_STRING_BASE64. which is 1
            +pValue = Pointer to a BSTR variable that contains the DER-Encoded PFX Message
            In this case the last $Enroll

         The PFX format is also known as PKCS #12. The CreatePFX method:
            +Opens the certificate store in memory for the default provider.
            +Adds the installed certificate to the store or builds the certificate chain adds a link to it.
            +Exports the certificate and the private key to a PFX message depending on the export options specified.
            +Encodes the exported message by using DER.
    ##>
    $Enroll = New-Object -ComObject 'X509Enrollment.CX509Enrollment.1'
    $Enroll.InitializeFromRequest($Certificate) #Initialize the enrollment object from an exisiting IX509CertificateRequest Object
    $Enroll.CertificateFriendlyName = $CommonName #Sets the display name of the certificate
    $Csr = $Enroll.CreateRequest() 
    $Enroll.InstallResponse(2, $Csr, 1, '')
    $Base64 = $Enroll.CreatePFX('', 0)
    $file = "$CommonName"+".txt"
    $base64 | out-file $file

####################INITIALIZE A NEW INSTANCE OF THE X509CERTIFICATE2 CLASS USING A BYTE ARRAY AND A PASSWORD###########
    <##
    the X509Certificate2 class is used with the PKCS12(PFX) files that contain the certificate's private Key.
    Calling the constructor with the correct password decrypts the private key and saves it to a container.
        -rawData = A Byte array tat contains data from an X509 Certificate
        -Password = Type System.Secure.String. The password required to access the X509 certificate data
    ##>
    #$Bytes = [Convert]::FromBase64String($Base64) #Gets the Certtificate and decodes it
    #$X509Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($Bytes, '')
        
   #return $X509Cert
}
