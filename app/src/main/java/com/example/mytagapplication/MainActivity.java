package com.example.mytagapplication;

import android.net.Uri;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.Ndef;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcV;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity implements ReaderCallback {

    public static String TAG = "TAG_SJ";
    public static NfcAdapter mNfcAdapter;
    public static Handler mHandler;
    public static String textViewString = "";
    public TextView mTextView;

    public static final int TAG_DISCOVERED = 0;
    public static final int TAG_READING = 1;
    public static final int TAG_COMPLETE = 2;
    public static final int TAG_LOST = 3;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        mTextView = findViewById(R.id.textView);

        mHandler = new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg){
                switch (msg.what) {
                    case TAG_DISCOVERED:
                        mTextView.setText("Reading the TAG ...");
                        break;
                    case TAG_COMPLETE:
                        textViewString += "\nTAG COMPLETE !!!\n";
                        mTextView.setText(textViewString);
                        break;
                    case TAG_LOST:
                        textViewString += "\nTAG LOST !!!\n";
                        mTextView.setText(textViewString);
                        break;
                    case TAG_READING:
                        mTextView.setText(textViewString);
                        break;
                    default:
                        break;
                }
            }
        };
    }

    @Override
    protected void onResume() {
        Log.d(TAG, "onResume");
        super.onResume();

        mNfcAdapter.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A |
                NfcAdapter.FLAG_READER_NFC_B | NfcAdapter.FLAG_READER_NFC_V, null);
    }

    public static String getHexBytes(byte[] bytes) {
        StringBuilder sb;
        sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public static String getHexByte(byte b) {
        StringBuilder sb;
        sb = new StringBuilder();
        sb.append(String.format("%02X ", b));
        return sb.toString();
    }

    public static String shortToHexBytes(short sr) {
        byte[] bytes = new byte[] {(byte) ((sr & 0xFF00) >> 8), (byte) (sr & 0x00FF)};
        return getHexBytes(bytes);
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        Log.d(TAG, "onTagDiscovered");
        textViewString = "";
        sendMessage(TAG_DISCOVERED);

        byte[] mId = tag.getId();
        Log.d(TAG, "TAG ID : " + getHexBytes(mId));
        String[] techList = tag.getTechList();

        textViewString += "[TAG TECH LIST]\n";
        for (String tech : techList) {
            textViewString += "    " + tech + "\n";
            Log.d(TAG, "TAG Tech : " + tech);
        }
        textViewString += "\n";

        // #Try to read the NFC A
        try {
            NfcA nfcA = NfcA.get(tag);
            if (nfcA != null) {
                nfcA.connect();
                if (nfcA.isConnected()) {
                    textViewString += "[NFC A]\n";
                    textViewString += "    ID : 0x " + getHexBytes(mId) + "\n";
                    byte[] atqa = nfcA.getAtqa();
                    textViewString += "    ATQA : 0x " + getHexBytes(atqa) +"\n";
                    short sak = nfcA.getSak();
                    textViewString += "    SAK : 0x " + shortToHexBytes(sak);
                    if (sak == (byte) 0x28 || sak == (byte) 0x38) {
                        textViewString += " - Emulated Mifare Tag\n";
                    } else {
                        textViewString += "\n";
                    }
                    textViewString += "    MAX TRANSCEIVE : " + nfcA.getMaxTransceiveLength() + " bytes\n";
                    textViewString += "    TIMEOUT : " + nfcA.getTimeout() + " milliseconds\n";
                }
                textViewString += "\n";
                nfcA.close();
            }

            // #Try to read the NDEF
            Ndef ndef = Ndef.get(tag);
            if (ndef != null) {
                ndef.connect();
                if (ndef.isConnected()) {
                    textViewString += "[NDEF BASIC]\n";
                    String tagType = ndef.getType();
                    if (tagType.contains("nfcforum")) {
                        textViewString += "    NFC FORUM TAG : " + tagType + "\n";
                    } else {
                        textViewString += "    NFC TAG TYPE : " + tagType + "\n";
                    }
                    if (ndef.isWritable()) {
                        textViewString += "    CAN NDEF READ & WRITE\n";
                        if (ndef.canMakeReadOnly()) {
                            textViewString += "    CAN MAKE READ ONLY\n";
                        } else {
                            textViewString += "    DO NOT MAKE READ ONLY\n";
                        }
                    } else {
                        textViewString += "    DO NOT NDEF WRITE\n";
                    }

                    textViewString += "\n";
                    NdefMessage ndefCachedMessage = ndef.getCachedNdefMessage();
                    NdefRecord[] ndefRecords = ndefCachedMessage.getRecords();
                    int count = 0;
                    for (NdefRecord record : ndefRecords) {
                        textViewString += "[NDEF RECORD] : " + count + "\n";
                        short tnf = record.getTnf();
                        textViewString += "    TNF : 0x " + shortToHexBytes(tnf);
                        if (tnf == NdefRecord.TNF_EMPTY) {
                            textViewString += " (TNF_EMPTY)\n";
                        } else if (tnf == NdefRecord.TNF_WELL_KNOWN) {
                            textViewString += " (TNF_WELL_KNOWN)\n";
                        } else if (tnf == NdefRecord.TNF_MIME_MEDIA) {
                            textViewString += " (TNF_MIME_MEDIA)\n";
                        } else if (tnf == NdefRecord.TNF_ABSOLUTE_URI) {
                            textViewString += " (TNF_ABSOLUTE_URI)\n";
                        } else if (tnf == NdefRecord.TNF_EXTERNAL_TYPE) {
                            textViewString += " (TNF_EXTERNAL_TYPE)\n";
                        } else if (tnf == NdefRecord.TNF_UNKNOWN) {
                            textViewString += " (TNF_UNKNOWN)\n";
                        } else if (tnf == NdefRecord.TNF_UNCHANGED) {
                            textViewString += " (TNF_UNCHANGED)\n";
                        }

                        byte[] type = record.getType();
                        textViewString += "    TYPE : 0x " + getHexBytes(type);
                        if (Arrays.equals(type, NdefRecord.RTD_TEXT)) {
                            textViewString += " - T (RTD_TEXT)";
                        } else if (Arrays.equals(type, NdefRecord.RTD_HANDOVER_REQUEST)) {
                            textViewString += " - Hr (RTD_HANDOVER_REQUEST)";
                        } else if (Arrays.equals(type, NdefRecord.RTD_HANDOVER_SELECT)) {
                            textViewString += " - Hs (RTD_HANDOVER_SELECT)";
                        } else if (Arrays.equals(type, "android.com:pkg".getBytes())) {
                            textViewString += " - AAR";
                        } else if (Arrays.equals(type, NdefRecord.RTD_URI)) {
                            textViewString += " - U (RTD_URI)";
                        } else if (Arrays.equals(type, NdefRecord.RTD_SMART_POSTER)) {
                            textViewString += " - Sp (RTD_SMART_POSTER)";
                        }
                        textViewString += "\n";

                        String mime = record.toMimeType();
                        if (mime != null) {
                            textViewString += "    MIME : " + mime + "\n";
                        }
                        Uri uri = record.toUri();
                        if (uri != null) {
                            textViewString += "    URI : " + uri + "\n";
                        }
                        byte[] payload = record.getPayload();
                        textViewString += "    PAYLOAD : " + new String(payload, StandardCharsets.UTF_8) + "\n";
                        textViewString += "\n";
                        count++;
                    }

                    textViewString += "\n";
                    textViewString += ndefCachedMessage.toString() + "\n";
                }
                ndef.close();
            }

            MifareClassic MC = MifareClassic.get(tag);
            if (MC != null) {
                MC.connect();
                if (MC.isConnected()) {
                    int type = MC.getType();
                    int size = MC.getSize();
                    int sectorCount = MC.getSectorCount();
                    int blockCount = MC.getBlockCount();
                    String tagType = "";
                    if (type == 0) {
                        tagType = "CLASSIC";
                    } else if (type == 1) {
                        tagType = "PLUS";
                    } else if (type == 2) {
                        tagType = "PRO";
                    } else {
                        tagType = "UNKNOWN";
                    }
                    textViewString += "\n[MIFARE " + tagType + "]\n"
                            + "    All Size is " + size + " bytes\n"
                            + "    Block Size is " + size / blockCount + " bytes\n"
                            + "    Sector Count is " + sectorCount + "\n"
                            + "    Block Count is " + blockCount +"\n\n";
                    Log.d(TAG, "Mifare " + tagType + " is connected, All Size is " + size + " bytes, Block Size is "
                            + size / blockCount + " bytes, Sector Count is " + sectorCount + ", Block Count is " + blockCount);

                    for (int sector = 0; sector < sectorCount; sector++) {
                        if (MC.authenticateSectorWithKeyA(sector, MifareClassic.KEY_DEFAULT)) {
                            Log.d(TAG, "SECTOR " + sector + " authenticate with KEY_DEFAULT");
                            textViewString += "SECTOR [" + sector  +"] - KEY_DEFAULT\n";
                            for (int block = MC.sectorToBlock(sector); block < MC.sectorToBlock(sector) + MC.getBlockCountInSector(sector); block++) {
                                byte[] readBlock = MC.readBlock(block);
                                textViewString += "  [" + block + "] : " + getHexBytes(readBlock) + "\n";
                                Log.d(TAG,"BLOCK " + block + " : " + getHexBytes(readBlock));
                            }
                        } else if (MC.authenticateSectorWithKeyA(sector, MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY)) {
                            Log.d(TAG, "SECTOR " + sector + " authenticate with KEY_MAD");
                            textViewString += "SECTOR [" + sector  +"] - KEY_MAD\n";
                            for (int block = MC.sectorToBlock(sector); block < MC.sectorToBlock(sector) + MC.getBlockCountInSector(sector); block++) {
                                byte[] readBlock = MC.readBlock(block);
                                textViewString += "  [" + block + "] : " + getHexBytes(readBlock) + "\n";
                                Log.d(TAG,"BLOCK " + block + " : " + getHexBytes(readBlock));
                            }
                        } else if (MC.authenticateSectorWithKeyA(sector, MifareClassic.KEY_NFC_FORUM)) {
                            Log.d(TAG, "SECTOR " + sector + " authenticate with KEY_NFC_FORUM");
                            textViewString += "SECTOR [" + sector  +"] - KEY_NDEF\n";
                            for (int block = MC.sectorToBlock(sector); block < MC.sectorToBlock(sector) + MC.getBlockCountInSector(sector); block++) {
                                byte[] readBlock = MC.readBlock(block);
                                textViewString += "  [" + block + "] : " + getHexBytes(readBlock) + "\n";
                                Log.d(TAG,"BLOCK " + block + " : " + getHexBytes(readBlock));
                            }
                        } else {
                            textViewString += "SECTOR [" + sector  +"] - NOT Authenticate\n";
                            Log.d(TAG, "SECTOR " + sector + " can't authenticate");
                        }
                        sendMessage(TAG_READING);
                    }
                } else {
                    Log.d(TAG, "Mifare is not connected");
                }
                MC.close();
            }

            NfcV nfcV = NfcV.get(tag);
            if (nfcV != null) {
                nfcV.connect();
                if (nfcV.isConnected()) {
                    Log.d(TAG, "NfcV is Connected");
                    byte dsfId = nfcV.getDsfId();
                    byte flag = nfcV.getResponseFlags();
                    textViewString += "[Nfc V]\n";
                    textViewString += "  UID : " + getHexBytes(mId) + "\n";
                    textViewString += "  DSF_ID : " + getHexByte(dsfId) + "\n";
                    textViewString += "  FLAG : " + getHexByte(flag) + "\n\n";

                    byte[] response;
                    byte[] CMD;
                    // READ SINGLE BLOCK
                    for (int i = 0; i <= 250; i++) {
                        CMD = doReadSingleBlockFromNfcV(mId, (byte) i);
                        response = nfcV.transceive(CMD);
                        if (doCheckErrorResponseFromNfcV(response)) {
                            textViewString += "BLOCK [" + i + "]\n";
                            textViewString += "  " + getHexBytes(response);
                            textViewString += " (ERROR, ";
                            textViewString += getErrorCodeFromNfcV(response) + ")\n";
                            break;
                        } else {
                            textViewString += "BLOCK [" + i + "]\n";
                            textViewString += "  " + getHexBytes(response) + "\n";
                        }
                        sendMessage(TAG_READING);
                    }
                    // READ MULTIPLE BLOCKS
                    /*
                    for (int i = 0; i <= 82; i++) {
                        int k = 3*i;
                        CMD = doReadMultipleBlockFromNfcV((byte) k, (byte) 0x02);
                        response = nfcV.transceive(CMD);
                        if (doCheckResponseFromNfcV(response)) {
                            textViewString += "BLOCK [" + k + "]\n";
                            textViewString += "  ERROR\n";
                        } else {
                            textViewString += "BLOCK [" + k + "]\n";
                            textViewString += "  " + getHexBytes(response) + "\n";
                        }
                        sendMessage(TAG_READING);
                    }
                    */
                }
            }
        } catch (TagLostException e) {
            Log.d(TAG, "Tag is lost");
            sendMessage(TAG_LOST);
            e.printStackTrace();
            return;
        } catch (IOException e) {
            Log.d(TAG, "IOException");
            e.printStackTrace();
            return;
        }
        sendMessage(TAG_COMPLETE);
    }

    byte[] doReadSingleBlockFromNfcV (byte[] uid, byte block) {
        byte[] CMD = new byte[11];
        CMD[0] = (byte) 0x22;
        CMD[1] = (byte) 0x20;
        CMD[2] = uid[0];
        CMD[3] = uid[1];
        CMD[4] = uid[2];
        CMD[5] = uid[3];
        CMD[6] = uid[4];
        CMD[7] = uid[5];
        CMD[8] = uid[6];
        CMD[9] = uid[7];
        CMD[10] = block;
        return CMD;
    }

    boolean doCheckErrorResponseFromNfcV(byte[] value) {
        boolean result = false;
        for (int i = 0; i < value.length; i++) {
            if (value[0] >= (byte) 0x01) {
                result = true;
                break;
            }
        }
        return result;
    }

    String getErrorCodeFromNfcV(byte[] value) {
        String result = "";
        if (value[1] == (byte) 0x01) {
            result = "CMD NOT SUPPORT";
        } else if (value[1] == (byte) 0x0F) {
            result = "NO INFORMATION";
        } else if (value[1] == (byte) 0x10) {
            result = "BLOCK DON'T EXIST";
        } else if (value[1] >= (byte) 0xA0) {
            result = "PROPRIETARY ERROR";
        }
        return result;
    }

    byte[] doReadMultipleBlockFromNfcV (byte firstBlock, byte NB) {
        byte[] CMD = new byte[4];
        CMD[0] = (byte) 0x02;
        CMD[1] = (byte) 0x23;
        CMD[2] = firstBlock;
        CMD[3] = NB;
        return CMD;
    }

    void sendMessage(int what) {
        Message msg = mHandler.obtainMessage();
        msg.what = what;
        mHandler.sendMessage(msg);
    }

}
