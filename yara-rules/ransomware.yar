/*
 * ransomware.yar — YARA rules for ransomware detection in Tetragon
 *
 * Strategy: detect strings that appear in ransomware binaries but almost never
 * in legitimate software. Rules are intentionally conservative (high specificity,
 * low recall) to minimise false positives in a SIGKILL-on-match scenario.
 *
 * Three layers:
 *   1. String patterns from known ransomware families
 *   2. Behavioural fingerprints (shadow copy deletion, ransom note names)
 *   3. Encryption + mass-file-operation combination
 */

rule Ransomware_ShadowCopy_Deletion
{
    meta:
        description = "Binary references vssadmin/wmic shadow copy deletion — classic ransomware pre-encryption step"
        severity    = "critical"
        family      = "generic"

    strings:
        $vss1 = "vssadmin delete shadows" nocase
        $vss2 = "vssadmin.exe delete" nocase
        $vss3 = "wmic shadowcopy delete" nocase
        $vss4 = "wbadmin delete catalog" nocase
        $vss5 = "bcdedit /set {default} recoveryenabled No" nocase
        $vss6 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase

    condition:
        any of them
}

rule Ransomware_NoteNames
{
    meta:
        description = "Binary embeds well-known ransom note filenames"
        severity    = "high"
        family      = "generic"

    strings:
        $note1 = "README_FOR_DECRYPT" nocase
        $note2 = "HOW_TO_DECRYPT" nocase
        $note3 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $note4 = "RECOVER_FILES" nocase
        $note5 = "DECRYPT_INSTRUCTION" nocase
        $note6 = "!!READ_ME_TO_RECOVER_FILES" nocase
        $note7 = "RESTORE_FILES" nocase
        $note8 = "FILES_ENCRYPTED.html" nocase

    condition:
        2 of them
}

rule Ransomware_WannaCry
{
    meta:
        description = "WannaCry ransomware binary markers"
        severity    = "critical"
        family      = "WannaCry"
        reference   = "https://www.secureworks.com/research/wcry-ransomware-analysis"

    strings:
        $wcry1 = "WannaCry" nocase
        $wcry2 = "wanacry" nocase
        $wcry3 = "WNCRY" nocase
        $wcry4 = "taskdl.exe"
        $wcry5 = "taskse.exe"
        $wcry6 = "msg/m_bulgarian.wnry"
        $wcry7 = "@WanaDecryptor@"
        $wcry8 = { 45 78 69 74 57 69 6E 64 6F 77 73 55 70 64 61 74 65 } // "ExitWindowsUpdate" hex

    condition:
        3 of them
}

rule Ransomware_LockBit
{
    meta:
        description = "LockBit ransomware family markers"
        severity    = "critical"
        family      = "LockBit"

    strings:
        $lb1 = "LockBit" nocase
        $lb2 = "Restore-My-Files.txt" nocase
        $lb3 = "lockbit" nocase
        $lb4 = ".lockbit" nocase
        $lb5 = "LockBit_Ransomware" nocase

    condition:
        2 of them
}

rule Ransomware_REvil_Sodinokibi
{
    meta:
        description = "REvil/Sodinokibi ransomware markers"
        severity    = "critical"
        family      = "REvil"

    strings:
        $rev1 = "sodinokibi" nocase
        $rev2 = "REvil" nocase
        $rev3 = "[.]readme" nocase
        $rev4 = "readme_to_decrypt" nocase
        $rev5 = { 72 61 6E 64 6F 6D 45 78 74 } // "randomExt"

    condition:
        2 of them
}

rule Ransomware_EncryptionAndMassWrite
{
    meta:
        description = "Binary combines AES/RSA encryption calls with mass filesystem traversal — behavioural pattern"
        severity    = "high"
        family      = "generic-behavioural"

    strings:
        // Encryption API references
        $enc1 = "AES_set_encrypt_key" nocase
        $enc2 = "AES_cbc_encrypt" nocase
        $enc3 = "EVP_EncryptInit" nocase
        $enc4 = "RSA_public_encrypt" nocase
        $enc5 = "CryptEncrypt" nocase

        // Mass file rename/delete patterns
        $fs1 = "os.Rename" nocase
        $fs2 = "filepath.Walk" nocase
        $fs3 = "ioutil.ReadDir" nocase
        $fs4 = "os.Remove" nocase
        $fs5 = "FindFirstFile" nocase
        $fs6 = "FindNextFile" nocase

        // Ransom extension suffixes embedded as strings
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".enc" nocase
        $ext4 = ".crypt" nocase

    condition:
        (1 of ($enc*)) and (2 of ($fs*)) and (1 of ($ext*))
}

rule Ransomware_TorOnionContact
{
    meta:
        description = "Binary embeds Tor .onion address — typical ransomware C2 payment contact"
        severity    = "medium"
        family      = "generic"

    strings:
        $onion1 = /[a-z2-7]{16,56}\.onion/ nocase
        $pay1   = "bitcoin" nocase
        $pay2   = "monero" nocase
        $pay3   = "wallet" nocase

    condition:
        $onion1 and (1 of ($pay*))
}
