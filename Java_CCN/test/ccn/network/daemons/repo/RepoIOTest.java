package test.ccn.network.daemons.repo;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;

import javax.xml.stream.XMLStreamException;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.parc.ccn.data.ContentName;
import com.parc.ccn.data.ContentObject;
import com.parc.ccn.data.MalformedContentNameStringException;
import com.parc.ccn.data.query.Interest;
import com.parc.ccn.data.security.PublisherID;
import com.parc.ccn.data.security.PublisherPublicKeyDigest;
import com.parc.ccn.library.io.CCNDescriptor;
import com.parc.ccn.library.io.CCNVersionedInputStream;
import com.parc.ccn.library.io.repo.RepositoryOutputStream;
import com.parc.ccn.library.profiles.SegmentationProfile;
import com.parc.ccn.network.daemons.repo.RFSImpl;
import com.parc.ccn.network.daemons.repo.Repository;
import com.parc.ccn.network.daemons.repo.RepositoryException;

/**
 * 
 * @author rasmusse
 * 
 * To run this test you must first unzip repotest.zip into the directory "repotest"
 * and then run the ccnd and the repository with that directory as its root.
 */

public class RepoIOTest extends RepoTestBase {
	
	protected static String _repoTestDir = "repotest";
	protected static byte [] data = new byte[4000];
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		//Library.logger().setLevel(Level.FINEST);
		RepoTestBase.setUpBeforeClass();
		byte value = 1;
		for (int i = 0; i < data.length; i++)
			data[i] = value++;
		RepositoryOutputStream ros = putLibrary.repoOpen(ContentName.fromNative("/testNameSpace/stream"), 
														null, putLibrary.getDefaultPublisher());
		ros.setBlockSize(100);
		ros.setTimeout(4000);
		ros.write(data, 0, data.length);
		ros.close();
	}
	
	@AfterClass
	public static void cleanup() throws Exception {
	}
	
	@Before
	public void setUp() throws Exception {
	}
	
	@Test
	public void testReadViaRepo() throws Throwable {
		System.out.println("Testing reading objects from repo");
		ContentName name = ContentName.fromNative("/repoTest/data1");
		
		// Since we have 2 pieces of data with the name /repoTest/data1 we need to compute both
		// digests to make sure we get the right data.
		ContentName name1 = new ContentName(name, ContentObject.contentDigest("Here's my data!"));
		ContentName clashName = ContentName.fromNative("/" + RFSImpl.META_DIR + "/repoTest/data1");
		ContentName digestName = new ContentName(name, ContentObject.contentDigest("Testing2"));
		String tooLongName = "0123456789";
		for (int i = 0; i < 30; i++)
			tooLongName += "0123456789";
		
		// Have 2 pieces of data with the same name here too.
		ContentName longName = ContentName.fromNative("/repoTest/" + tooLongName);
		longName = new ContentName(longName, ContentObject.contentDigest("Long name!"));
		ContentName badCharName = ContentName.fromNative("/repoTest/" + "*x?y<z>u");
		ContentName badCharLongName = ContentName.fromNative("/repoTest/" + tooLongName + "*x?y<z>u");
			
		checkDataWithDigest(name1, "Here's my data!");
		checkData(clashName, "Clashing Name");
		checkDataWithDigest(digestName, "Testing2");
		checkDataWithDigest(longName, "Long name!");
		checkData(badCharName, "Funny characters!");
		checkData(badCharLongName, "Long and funny");
		
		ArrayList<ContentObject>keys = getLibrary.enumerate(new Interest(keyprefix), 4000);
		for (ContentObject keyObject : keys) {
			checkDataAndPublisher(name, "Testing2", new PublisherPublicKeyDigest(keyObject.content()));
		}
	}
	
	@Test
	public void testPolicyViaCCN() throws Exception {
		System.out.println("Testing namespace policy setting");
		checkNameSpace("/repoTest/data2", true);
		FileInputStream fis = new FileInputStream(_topdir + "/test/ccn/network/daemons/repo/policyTest.xml");
		byte [] content = new byte[fis.available()];
		fis.read(content);
		fis.close();
		RepositoryOutputStream ros = putLibrary.repoOpen(ContentName.fromNative(_globalPrefix + '/' + 
				_repoName + '/' + Repository.REPO_DATA + '/' + Repository.REPO_POLICY), null,
				putLibrary.getDefaultPublisher());
		ros.write(content, 0, content.length);
		ros.close();
		Thread.sleep(4000);
		checkNameSpace("/repoTest/data3", false);
		checkNameSpace("/testNameSpace/data1", true);
	}
	
	@Test
	public void testWriteToRepo() throws Exception {
		System.out.println("Testing writing streams to repo");
		Thread.sleep(5000);
		for (int i = 0; i < 40; i++) {
			byte [] testData = new byte[100];
			System.arraycopy(data, i * 100, testData, 0, 100);
			ContentName name = SegmentationProfile.segmentName(ContentName.fromNative("/testNameSpace/stream"), i);
			Assert.assertTrue(checkDataFromFile(new File(_repoTestDir + File.separator + RFSImpl.encodeName(name).toString()), 
					testData));
		}
	}
	
	@Test
	public void testReadFromRepo() throws Exception {
		System.out.println("Testing reading a stream from the repo");
		Thread.sleep(5000);
		CCNDescriptor input = new CCNDescriptor(ContentName.fromNative("/testNameSpace/stream"), null, getLibrary);
		byte[] testBytes = new byte[data.length];
		input.read(testBytes);
		Assert.assertArrayEquals(data, testBytes);
	}
	
	@Test
	// The purpose of this test is to do versioned reads from repo
	// of data not already in the ccnd cache, thus testing 
	// what happens if we pull latest version and try to read
	// content in order
	public void testVersionedRead() throws InterruptedException, MalformedContentNameStringException, XMLStreamException, IOException {
		System.out.println("Testing reading a versioned stream");
		Thread.sleep(5000);
		ContentName versionedNameNormal = ContentName.fromNative("/testNameSpace/testVersionNormal");
		CCNVersionedInputStream vstream = new CCNVersionedInputStream(versionedNameNormal);
		InputStreamReader reader = new InputStreamReader(vstream);
		for (long i=SegmentationProfile.baseSegment(); i<5; i++) {
			String segmentContent = "segment"+ new Long(i).toString();
			char[] cbuf = new char[8];
			int count = reader.read(cbuf, 0, 8);
			System.out.println("for " + i + " got " + count + " (eof " + vstream.eof() + "): " + new String(cbuf));
			Assert.assertEquals(segmentContent, new String(cbuf));
		}
		Assert.assertEquals(-1, reader.read());
	}
	
	private void checkData(ContentName name, String data) throws IOException, InterruptedException{
		checkData(new Interest(name), data.getBytes());
	}
	
	private void checkDataWithDigest(ContentName name, String data) throws IOException, InterruptedException{
		// When generating an Interest for the exact name with content digest, need to set additionalNameComponents
		// to 0, signifying that name ends with explicit digest
		checkData(new Interest(name, 0, (PublisherID)null), data.getBytes());
	}

	private void checkData(Interest interest, byte[] data) throws IOException, InterruptedException{
		ContentObject testContent = getLibrary.get(interest, 10000);
		Assert.assertFalse(testContent == null);
		Assert.assertTrue(Arrays.equals(data, testContent.content()));		
	}

	private void checkDataAndPublisher(ContentName name, String data, PublisherPublicKeyDigest publisher) 
				throws IOException, InterruptedException {
		Interest interest = new Interest(name, new PublisherID(publisher));
		ContentObject testContent = getLibrary.get(interest, 10000);
		Assert.assertFalse(testContent == null);
		Assert.assertEquals(data, new String(testContent.content()));
		Assert.assertTrue(testContent.signedInfo().getPublisherKeyID().equals(publisher));
	}
	protected boolean checkDataFromFile(File testFile, byte[] data) throws RepositoryException {
		Assert.assertTrue(testFile.isDirectory());
		File[] files = testFile.listFiles();
		Assert.assertFalse(files == null);
		ContentObject co = RFSImpl.getContentFromFile(files[0]);
		Assert.assertTrue(co != null);
		Assert.assertTrue(Arrays.equals(data, co.content()));
		return true;
	}
	
	protected void checkNameSpace(String contentName, boolean expected) throws Exception {
		ContentName name = ContentName.fromNative(contentName);
		RepositoryOutputStream ros = null;
		try {
			ros = putLibrary.repoOpen(name, null, putLibrary.getDefaultPublisher());
		} catch (IOException ex) {
			if (expected)
				Assert.fail(ex.getMessage());
			return;
		}
		byte [] data = "Testing 1 2 3".getBytes();
		ros.write(data, 0, data.length);
		ContentName baseName = ros.getBaseName();
		ros.close();
		Thread.sleep(1000);
		File testFile = new File("repotest" + RFSImpl.encodeName(baseName).toString());
		if (expected)
			Assert.assertTrue(testFile.exists());
		else
			Assert.assertFalse(testFile.exists());
	}
}
