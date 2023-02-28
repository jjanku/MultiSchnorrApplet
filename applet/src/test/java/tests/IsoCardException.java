package tests;

import javax.smartcardio.CardException;

public class IsoCardException extends CardException {
    public final short status;

    public IsoCardException(int status) {
        super(String.format("Card returned status %#06x", status));
        this.status = (short) status;
    }
}
