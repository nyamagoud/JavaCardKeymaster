package com.android.javacard.test;

import java.nio.ByteBuffer;
import java.util.ArrayList;

public class KMParameterValue {

  public ArrayList<Byte> byteValues;
  public byte byteValue;
  public int integer;
  public long longinteger;
  public ByteBuffer buf;
  
  public KMParameterValue() { }
  
  public KMParameterValue(KMParameterValue other) {
    byteValues = new ArrayList<>();
    byteValues.addAll(other.byteValues);
    byteValue = other.byteValue;
    integer = other.integer;
    longinteger = other.longinteger;
    buf = ByteBuffer.allocate(other.buf.capacity());
    other.buf.rewind();
    buf.put(other.buf);
    other.buf.rewind();
    buf.flip();
  }
}
