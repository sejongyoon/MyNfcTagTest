package com.example.mytagapplication;

import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.MifareClassic;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.IOException;

public class MainActivity extends AppCompatActivity implements ReaderCallback {

    public static String TAG = "SJ";
    public static NfcAdapter mNfcAdapter;
    public static TextView mTextView;
    public static Handler mHandler;
    public static String textViewString = "";

    public static final int TAG_READING = 0;
    public static final int TAG_COMPLETE = 1;
    public static final int TAG_LOST = 2;

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
                    case TAG_READING:
                        mTextView.setText("Reading the TAG ...");
                        break;
                    case TAG_COMPLETE:
                        textViewString += "TAG COMPLETE !!!\n";
                        mTextView.setText(textViewString);
                        break;
                    case TAG_LOST:
                        textViewString += "TAG LOST !!!\n";
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
        textViewString = "";
        mTextView.setText("onResume");
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

    @Override
    public void onTagDiscovered(Tag tag) {
        Log.d(TAG, "onTagDiscovered");
        sendMessage(TAG_READING);

        byte[] mId = tag.getId();
        Log.d(TAG, "TAG ID : " + getHexBytes(mId));
        String[] techList = tag.getTechList();
        for (String tech : techList) {
            Log.d(TAG, "TAG Tech : " + tech);
        }

        // #1 Try to read the kind of Mifare Classic Tag
        textViewString = "";
        try {
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
                        tagType = "Classic";
                    } else if (type == 1) {
                        tagType = "Plus";
                    } else if (type == 2) {
                        tagType = "Pro";
                    } else {
                        tagType = "Unknown";
                    }
                    textViewString += "Mifare " + tagType + " is connected\n"
                            + "    ID is " + getHexBytes(mId) + "\n"
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
                            Log.d(TAG, "SECTOR " + sector + " can't authenticate");
                        }
                    }
                } else {
                    Log.d(TAG, "Mifare is not connected");
                }
            }
        } catch (TagLostException e) {
            Log.d(TAG, "Tag is lost");
            sendMessage(TAG_LOST);
            e.printStackTrace();
        } catch (IOException e) {
            Log.d(TAG, "IOException");
            e.printStackTrace();
        }
        sendMessage(TAG_COMPLETE);
    }

    void sendMessage(int what) {
        Message msg = mHandler.obtainMessage();
        msg.what = what;
        mHandler.sendMessage(msg);
    }

}
