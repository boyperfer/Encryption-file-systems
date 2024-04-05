import java.io.File;

import static java.lang.System.exit;

public class TestBuild {
    final static String FILE_NAME = "abcabdabdbbabcacbcccbacabcbadq.txt.jar.bmp.zip.tar.gz";
    final static String USER_NAME = "admin";
    final static String PASSWORD = "1234";
    static String TEST_DATA = "a".repeat(6969);

    public static void main(String[] args) throws Exception {
        EFS efs = new EFS(null);
        efs.username = USER_NAME;
        efs.password = PASSWORD;

        // Run tests lol
        testCreate(efs);
        testFindUser(efs);
        System.out.print("Length Test (Test Case - New File): ");
        testLength(efs, 0);

        // Run write tests.
        testWrite(efs);

        System.out.print("Length Test (Test Case - Writes Finished): ");
        testLength(efs, TEST_DATA.length());

        // Run cut test.
        testCut(efs);

        // Run integrity checks.
        System.out.println("=".repeat(200) + "\n");
        testIntegrity(efs, false);
        testIntegrity(efs, true);

        // Run final cut test.
        testFinalCut(efs);

        // Delete the file :)
        File root = new File(FILE_NAME);
        File toDelete = new File(root, "0");
        int fileBlock = 1;
        while (toDelete.exists()) {
            toDelete.delete();
            toDelete = new File(root, Integer.toString(fileBlock));
            fileBlock++;
        }
        root.delete();

        exit(0);
    }

    private static void testCreate(EFS efs) throws Exception {
        efs.create(FILE_NAME, USER_NAME, PASSWORD);
        if (new File(FILE_NAME, "0").exists()) {
            System.out.println("File Creation: Success");
        }
        else {
            System.out.println("File Creation: Fail");
        }
        System.out.println();
    }

    private static void testFindUser(EFS efs) throws Exception {
		System.out.println("test finduser 1");
        String actualUsername = efs.findUser(FILE_NAME);
		System.out.println("test finduser 2");
        if (!actualUsername.equals(USER_NAME)) {
            System.out.println("Find User: Fail");
        }
        else {
            System.out.println("Find User: Success");
        }
        System.out.println("\tExpected: " + USER_NAME);
        System.out.println("\tActual:   " + actualUsername);
        System.out.println();
    }

    private static void testLength(EFS efs, int expectedLength) throws Exception {
        int actualLength = efs.length(FILE_NAME, PASSWORD);
        if (actualLength != expectedLength) {
            System.out.println("Fail");
        }
        else {
            System.out.println("Success");
        }
        System.out.println("\tExpected: " + expectedLength);
        System.out.println("\tActual:   " + actualLength);
        System.out.println();
    }

    private static void testRead(EFS efs, int len, String expectedRead) throws Exception {
        String actualRead = Utility.byteArray2String(efs.read(FILE_NAME, 0, len, PASSWORD));
        if (!actualRead.equals(expectedRead)) {
            System.out.println("Fail");
            System.out.println("\tExpected: " + expectedRead);
            System.out.println("\tActual:   " + actualRead);
        }
        else {
            System.out.println("Success");
        }
        System.out.println();
    }

    private static void testWrite(EFS efs) throws Exception {
        // Case 0: Writing nothing
        System.out.println("=".repeat(200));
        System.out.print("\nWrite Case 0 - Write and Read Nothing: ");
        efs.write(FILE_NAME, 0, new byte[0], PASSWORD);
        testRead(efs, 0, "");

        // Case 1: Append on new file
        System.out.print("Write Case 1 - Append on new file: ");
        efs.write(FILE_NAME, 0, TEST_DATA.getBytes(), PASSWORD);
        testRead(efs, TEST_DATA.length(), TEST_DATA);

        // Case 2: Append on existing file
        String overwrite = "a".repeat(10);
        TEST_DATA += overwrite;
        System.out.print("Write Case 2 - Append on existing file: ");
        efs.write(FILE_NAME, TEST_DATA.length()-overwrite.length(), overwrite.getBytes(), PASSWORD);
        testRead(efs, TEST_DATA.length(), TEST_DATA);

        // Case 3: Within one block
        overwrite = "b".repeat(100);
        TEST_DATA = overwrite + TEST_DATA.substring(overwrite.length());
        System.out.print("Write Case 3 - Overwrite within one block: ");
        efs.write(FILE_NAME, 0, overwrite.getBytes(), PASSWORD);
        testRead(efs, TEST_DATA.length(), TEST_DATA);

        // Case 4: Between 2 blocks
        overwrite = "c".repeat(100);
        int overwritePos = 1000;
        TEST_DATA = TEST_DATA.substring(0, overwritePos) + overwrite + TEST_DATA.substring(overwritePos+overwrite.length());
        System.out.print("Write Case 4 - Overwrite between 2 blocks: ");
        efs.write(FILE_NAME, overwritePos, overwrite.getBytes(), PASSWORD);
        testRead(efs, TEST_DATA.length(), TEST_DATA);

        // Case 5: Between 3 blocks
        overwrite = "d".repeat(1200);
        // overwritePos = 1000;
        TEST_DATA = TEST_DATA.substring(0, overwritePos) + overwrite + TEST_DATA.substring(overwritePos+overwrite.length());
        System.out.print("Write Case 5 - Overwrite between 3 blocks: ");
        efs.write(FILE_NAME, overwritePos, overwrite.getBytes(), PASSWORD);
        testRead(efs, TEST_DATA.length(), TEST_DATA);

        // Case 6: Writing in last block
        overwrite = "e".repeat(69);
        overwritePos = TEST_DATA.length()-69;
        TEST_DATA = TEST_DATA.substring(0, overwritePos) + overwrite + TEST_DATA.substring(overwritePos+overwrite.length());
        System.out.print("Write Case 6 - Within last block: ");
        efs.write(FILE_NAME, overwritePos, overwrite.getBytes(), PASSWORD);
        testRead(efs, TEST_DATA.length(), TEST_DATA);

        // Case 7: Writing in last block beyond bounds
        overwrite = "f".repeat(690);
        overwritePos = TEST_DATA.length()-50;
        TEST_DATA = TEST_DATA.substring(0, overwritePos) + overwrite;
        System.out.print("Write Case 7 - Between last block and beyond: ");
        efs.write(FILE_NAME, overwritePos, overwrite.getBytes(), PASSWORD);
        testRead(efs, TEST_DATA.length(), TEST_DATA);
    }

    private static void testCut(EFS efs) throws Exception {
        // Case 1: Cut of length file length
        System.out.println("=".repeat(200));
        System.out.print("\nCut Case 1 - Cut that does nothing: ");
        efs.cut(FILE_NAME, TEST_DATA.length(), PASSWORD);
        testRead(efs, TEST_DATA.length(), TEST_DATA);

        // Case 2: Cut of some arbitrary length
        int cutToLength = 3000;
        System.out.print("Cut Case 2 - Normal Cut to Length " + cutToLength + ": ");
        efs.cut(FILE_NAME, cutToLength, PASSWORD);
        TEST_DATA = TEST_DATA.substring(0, cutToLength);
        testRead(efs, TEST_DATA.length(), TEST_DATA);

        // Check the length of the file.
        System.out.print("Length Test (Test Case - After Cut): ");
        testLength(efs, TEST_DATA.length());
    }

    private static void testFinalCut(EFS efs) throws Exception {
        // Case 3: Cut to length 0.
        System.out.print("Cut Case 3 - Cut to 0: ");
        efs.cut(FILE_NAME, 0, PASSWORD);
        TEST_DATA = "";
        testRead(efs, 0, TEST_DATA);
    }

    private static void testIntegrity(EFS efs, boolean violate) throws Exception {
        // Overwrite content without properly using the write() call. Should violate integrity.
        if (violate) {
            System.out.print("Detection for Integrity Violation: ");
            byte[] randomShit = Utility.secureRandomNumber(1024);
            efs.save_to_file(randomShit, new File(FILE_NAME, "1"));
        }
        else {
            System.out.print("Normal Integrity Check: ");
        }

        boolean integrityResult = efs.check_integrity(FILE_NAME, PASSWORD);
        if ((integrityResult && !violate) || (!integrityResult && violate)) {
            System.out.println("Success");
        }
        else {
            System.out.println("Fail");
        }
        System.out.println();
    }
}
