package applet;

public class Protocol {
    public static final byte CLA = (byte) 0x00;

    public static final byte INS_GET_IDENTITY = (byte) 0x01;
    public static final byte INS_GET_GROUP = (byte) 0x03;
    public static final byte INS_DKGEN = (byte) 0x02;
    public static final byte INS_COMMIT = (byte) 0x04;
    public static final byte INS_SIGN = (byte) 0x05;

    public static final short ERR_POP = (short) 0xbad0;
    public static final short ERR_COMMIT = (short) 0xbad1;

    public static final short MSG_LEN = (short) 32;
}
