class Convert {
  
  public static void main(String[] args) {
    System.out.println("fails:");
    byte b1 =  10;
    byte b2 =  20;
    byte b3 = -10;
    byte b4 =  30;
    print(b1);
    print(b2);
    print(b3);
    print(b4);
    int i = ((b1 << 24) |
             (b2 << 16) |
             (b3 <<  8) |
             (b4));
    print(i);
    byte b5 = (byte) (i >> 24);
    byte b6 = (byte) (i >> 16);
    byte b7 = (byte) (i >>  8);
    byte b8 = (byte) i;
    print(b5);
    print(b6);
    print(b7);
    print(b8);
    // why does it fail above this line but work below?????
    System.out.println("works:");
    b1 =  10;
    b2 =  20;
    b3 = -10;
    b4 =  30;
    print(b1);
    print(b2);
    print(b3);
    print(b4);
    i = (((b1 & 0xff) << 24) |
         ((b2 & 0xff) << 16) |
         ((b3 & 0xff) <<  8) |
         ((b4 & 0xff)));
    print(i);
    b5 = (byte) (i >> 24);
    b6 = (byte) (i >> 16);
    b7 = (byte) (i >>  8);
    b8 = (byte) i;
    print(b5);
    print(b6);
    print(b7);
    print(b8);
  }
 
   private static void print(byte b) {
     String s = Integer.toBinaryString(b);
     int len = s.length();
     if (len > 8) s = s.substring(len-8,len);
     while(s.length() < 8) s = "0" + s;
     String t = "" + s.charAt(0);
     for (int i=1; i<8; i++) {
       if (i%4==0) t+=" ";
       t += s.charAt(i);
     }
     System.out.println(b + "\t: " + t);
  }
  
  private static void print(int i) {
    String s = Integer.toBinaryString(i);
    while(s.length() < 32) s = "0" + s;
    String t = "" + s.charAt(0);
    for (int j=1; j<32; j++) {
      if (j%8==0) t+=" | ";
      else if (j%4==0) t+=" ";
      t += s.charAt(j);
    }
    System.out.println(i + ": " + t);
  }
  
}