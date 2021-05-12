package com.android.javacard.test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMBoolTag;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMByteTag;
import com.android.javacard.keymaster.KMEnumArrayTag;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMInteger;
import com.android.javacard.keymaster.KMIntegerTag;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMTag;
import com.android.javacard.keymaster.KMType;

import javafx.util.Pair;

public class KMKeyParameterSet {

  private Map<Pair<Short, Short>, KMParameterValue> keyParameters;

  public KMKeyParameterSet() {
    keyParameters = new HashMap<>();
  }

  public KMKeyParameterSet(Map<Pair<Short, Short>, KMParameterValue> params) {
    keyParameters = params;
  }

  public Map<Pair<Short, Short>, KMParameterValue> getKeyParameters() {
    return keyParameters;
  }

  public static KMKeyParameterSet decodeKeyParameters(short params) {
    Map<Pair<Short, Short>, KMParameterValue> keyParams = new HashMap<>();
    KMParameterValue val;
    short arrPtr = KMKeyParameters.cast(params).getVals();
    short length = KMKeyParameters.cast(params).length();
    KMArray vals = KMArray.cast(arrPtr);
    short obj;
    short key;
    short type;
    short index = 0;
    while (index < length) {
      obj = vals.get(index);
      key = KMTag.getKey(obj);
      type = KMTag.getTagType(obj);
      switch (type) {
      case KMType.UINT_TAG:
        short intPtr = KMIntegerTag.cast(obj).getValue();
        val = new KMParameterValue();
        val.integer = KMInteger.cast(intPtr).getShort();
        break;
      case KMType.ENUM_ARRAY_TAG:
        ArrayList<Byte> byteVals = new ArrayList<>();
        short byteBlob = KMEnumArrayTag.cast(obj).getValues();
        for (short i = 0; i < KMByteBlob.cast(byteBlob).length(); i++) {
          byte byteVal = KMByteBlob.cast(byteBlob).get(i);
          byteVals.add(byteVal);
        }
        val = new KMParameterValue();
        val.byteValues = byteVals;
        break;
      case KMType.ENUM_TAG:
        byte enumValue = KMEnumTag.cast(obj).getValue();
        val = new KMParameterValue();
        val.byteValue = enumValue;
        break;
      case KMType.ULONG_TAG:
        short int32Ptr = KMIntegerTag.cast(obj).getValue();
        val = new KMParameterValue();
        ByteBuffer int32ByteBuf = ByteBuffer.allocate(8).put(
            KMInteger.cast(int32Ptr).getBuffer(),
            KMInteger.cast(int32Ptr).getStartOff(),
            KMInteger.cast(int32Ptr).length());
        int32ByteBuf.rewind();
        val.integer = int32ByteBuf.getInt();
        break;
      case KMType.DATE_TAG:
        short datePtr = KMIntegerTag.cast(obj).getValue();
        val = new KMParameterValue();
        ByteBuffer dateByteBuf = ByteBuffer.allocate(8).put(
            KMInteger.cast(datePtr).getBuffer(),
            KMInteger.cast(datePtr).getStartOff(),
            KMInteger.cast(datePtr).length());
        dateByteBuf.rewind();
        val.longinteger = dateByteBuf.getLong();
        break;
      case KMType.BYTES_TAG:
        short blobPtr = KMByteTag.cast(obj).getValue();
        ByteBuffer blobByteBuf = ByteBuffer.wrap(
            KMByteBlob.cast(blobPtr).getBuffer(),
            KMByteBlob.cast(blobPtr).getStartOff(),
            KMByteBlob.cast(blobPtr).length());
        val = new KMParameterValue();
        val.buf = blobByteBuf;
        val.buf.rewind();
        break;
      case KMType.BOOL_TAG:
        val = new KMParameterValue();
        val.byteValue = KMBoolTag.cast(obj).getVal();
        break;
      default:
        continue;
      }
      Pair<Short, Short> p = new Pair<>(type, key);
      keyParams.put(p, val);
      index++;
    }
    KMKeyParameterSet paramSet = new KMKeyParameterSet(keyParams);
    return paramSet;
  }

  public boolean compare(KMKeyParameterSet paramSet) {
    for (Map.Entry<Pair<Short, Short>, KMParameterValue> entry : keyParameters
        .entrySet()) {
      Pair<Short, Short> pair = entry.getKey();
      Short type = pair.getKey();
      KMParameterValue val = entry.getValue();
      KMParameterValue other = paramSet.keyParameters.get(pair);
      switch (type) {
      case KMType.UINT_TAG:
      case KMType.ULONG_TAG:
        if (val.integer != other.integer)
          return false;
        break;
      case KMType.ENUM_ARRAY_TAG:
        if (!val.byteValues.equals(other.byteValues))
          return false;
        break;
      case KMType.DATE_TAG:
        if (val.longinteger != other.longinteger)
          return false;
        break;
      case KMType.BYTES_TAG:
        val.buf.rewind();
        other.buf.rewind();
        if (0 != val.buf.compareTo(other.buf))
          return false;
        break;
      case KMType.BOOL_TAG:
      case KMType.ENUM_TAG:
        if (val.byteValue != other.byteValue)
          return false;
        break;
      default:
        continue;
      }
    }
    return true;
  }

  public void concat(KMKeyParameterSet other) {
    for (Map.Entry<Pair<Short, Short>, KMParameterValue> entry : other.keyParameters
        .entrySet()) {
      if (null == keyParameters.get(entry.getKey())) {
        Pair<Short, Short> pair = new Pair<>(entry.getKey().getKey(),
            entry.getKey().getValue());
        KMParameterValue val = new KMParameterValue(entry.getValue());
        keyParameters.put(pair, val);
      }
    }
  }

  public KMParameterValue getValue(short type, short key) {
    for (Map.Entry<Pair<Short, Short>, KMParameterValue> entry : keyParameters
        .entrySet()) {
      Pair<Short, Short> pair = entry.getKey();
      if (pair.getKey() == type && pair.getValue() == key) {
        return entry.getValue();
      }
    }
    return null;
  }

  public int size() {
    return keyParameters.size();
  }

  public int getKeySize() {
    return getValue(KMType.UINT_TAG, KMType.KEYSIZE).integer;
  }

  public int getRsaPublicKey() {
    return getValue(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT).integer;
  }

  public int getAlgorithm() {
    return getValue(KMType.ENUM_TAG, KMType.ALGORITHM).byteValue;
  }

  public ArrayList<Byte> getPaddings() {
    return getValue(KMType.ENUM_ARRAY_TAG, KMType.PADDING).byteValues;
  }

  public ArrayList<Byte> getDigests() {
    return getValue(KMType.ENUM_ARRAY_TAG, KMType.DIGEST).byteValues;
  }

  public ArrayList<Byte> getPurposes() {
    return getValue(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE).byteValues;
  }

  public int getCurve() {
    return getValue(KMType.ENUM_TAG, KMType.ECCURVE).byteValue;
  }

  public static class KeyParametersSetBuilder {
    private Map<Pair<Short, Short>, KMParameterValue> keyParameters_;

    public KeyParametersSetBuilder() {
      keyParameters_ = new HashMap<>();
    }

    private KeyParametersSetBuilder setUIntTagType(short key, int value) {
      KMParameterValue val = new KMParameterValue();
      val.integer = value;
      Pair<Short, Short> pair = new Pair<Short, Short>(KMType.UINT_TAG, key);
      keyParameters_.put(pair, val);
      return this;
    }

    private KeyParametersSetBuilder setULongTagType(short key, int value) {
      KMParameterValue val = new KMParameterValue();
      val.integer = value;
      Pair<Short, Short> pair = new Pair<Short, Short>(KMType.ULONG_TAG, key);
      keyParameters_.put(pair, val);
      return this;
    }

    private KeyParametersSetBuilder setDateTagType(short key, long value) {
      KMParameterValue val = new KMParameterValue();
      val.longinteger = value;
      Pair<Short, Short> pair = new Pair<Short, Short>(KMType.DATE_TAG, key);
      keyParameters_.put(pair, val);
      return this;
    }

    private KeyParametersSetBuilder setEnumArrayTagType(short key,
        byte... values) {
      ArrayList<Byte> list = new ArrayList<>();
      for (byte val : values)
        list.add(val);
      KMParameterValue val = new KMParameterValue();
      val.byteValues = list;
      Pair<Short, Short> pair = new Pair<Short, Short>(KMType.ENUM_ARRAY_TAG,
          key);
      keyParameters_.put(pair, val);
      return this;
    }

    private KeyParametersSetBuilder setEnumTagType(short key, byte value) {
      KMParameterValue val = new KMParameterValue();
      val.byteValue = value;
      Pair<Short, Short> pair = new Pair<Short, Short>(KMType.ENUM_TAG, key);
      keyParameters_.put(pair, val);
      return this;
    }

    private KeyParametersSetBuilder setBytesTag(short key, ByteBuffer value) {
      KMParameterValue val = new KMParameterValue();
      val.buf = ByteBuffer.allocate(value.capacity());
      value.rewind();
      val.buf.put(value);
      val.buf.flip();
      Pair<Short, Short> pair = new Pair<Short, Short>(KMType.BYTES_TAG, key);
      keyParameters_.put(pair, val);
      return this;
    }

    private KeyParametersSetBuilder setBoolTag(short key, byte value) {
      KMParameterValue val = new KMParameterValue();
      val.byteValue = value;
      Pair<Short, Short> pair = new Pair<Short, Short>(KMType.BOOL_TAG, key);
      keyParameters_.put(pair, val);
      return this;
    }

    public KeyParametersSetBuilder setKeySize(int keySize) {
      return setUIntTagType(KMType.KEYSIZE, keySize);
    }

    public KeyParametersSetBuilder setMinMacLength(int minMacLen) {
      return setUIntTagType(KMType.MIN_MAC_LENGTH, minMacLen);
    }

    public KeyParametersSetBuilder setCurve(byte curve) {
      return setEnumTagType(KMType.ECCURVE, curve);
    }

    public KeyParametersSetBuilder setAlgorithm(byte algorithm) {
      return setEnumTagType(KMType.ALGORITHM, algorithm);
    }

    public KeyParametersSetBuilder setDigest(byte... digests) {
      return setEnumArrayTagType(KMType.DIGEST, digests);
    }

    public KeyParametersSetBuilder setPadding(byte... paddings) {
      return setEnumArrayTagType(KMType.PADDING, paddings);
    }

    public KeyParametersSetBuilder setPurpose(byte... purposes) {
      return setEnumArrayTagType(KMType.PURPOSE, purposes);
    }

    public KeyParametersSetBuilder setActiveDateTime(long time) {
      return setDateTagType(KMType.ACTIVE_DATETIME, time);
    }

    public KeyParametersSetBuilder setCreationDateTime(long time) {
      return setDateTagType(KMType.CREATION_DATETIME, time);
    }

    public KeyParametersSetBuilder setRsaPubExp(int pubexp) {
      return setULongTagType(KMType.RSA_PUBLIC_EXPONENT, pubexp);
    }

    public KeyParametersSetBuilder setApplicationData(ByteBuffer byteBuf) {
      return setBytesTag(KMType.APPLICATION_DATA, byteBuf);
    }

    public KeyParametersSetBuilder setApplicationId(ByteBuffer byteBuf) {
      return setBytesTag(KMType.APPLICATION_ID, byteBuf);
    }

    public KeyParametersSetBuilder setNoAuthRequired() {
      return setBoolTag(KMType.NO_AUTH_REQUIRED, (byte) 1);
    }

    public KMKeyParameterSet build() {
      KMKeyParameterSet paramSet = new KMKeyParameterSet(keyParameters_);
      return paramSet;
    }
  }

}
