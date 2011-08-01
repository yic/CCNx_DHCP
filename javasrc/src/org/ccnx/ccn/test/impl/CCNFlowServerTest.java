/*
 * A CCNx library test.
 *
 * Copyright (C) 2009, 2010 Palo Alto Research Center, Inc.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation. 
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
 
package org.ccnx.ccn.test.impl;


import java.io.IOException;

import junit.framework.Assert;

import org.ccnx.ccn.impl.CCNFlowServer;
import org.ccnx.ccn.protocol.ContentName;
import org.ccnx.ccn.protocol.ContentObject;
import org.ccnx.ccn.protocol.Interest;
import org.ccnx.ccn.test.ThreadAssertionRunner;
import org.junit.Before;
import org.junit.Test;

public class CCNFlowServerTest extends CCNFlowControlTestBase {
	
	@Before
	public void setUp() throws Exception {
		_capacity = SEGMENT_COUNT*2;
		fc = new CCNFlowServer(_capacity, true, _handle);
	}
	
	@Test
	public void testMultipleGets() throws Throwable {	

		normalReset(name1);
		// add data to the flow server, and make sure we can get it out multiple times
		// Put these in slightly random order. It would be nice to truly randomize this but am
		// not going to bother with that right now.
		fc.put(segments[3]);
		fc.put(segments[0]);
		fc.put(segments[1]);
		fc.put(segments[2]);
		ContentObject co = testExpected(_handle.get(versions[0], 0), segments[0]);
		co = testNext(co, segments[1]);
		co = testNext(co, segments[2]);
		co = testNext(co, segments[3]);
		co = testExpected(_handle.get(versions[0], 0), segments[0]);
		co = testNext(co, segments[1]);
		co = testNext(co, segments[2]);
		co = testNext(co, segments[3]);
		
	}

	@Test
	public void testWaitForPutDrain() throws Throwable {	

		normalReset(name1);
		fc.put(segments[1]);
		fc.put(segments[3]);
		fc.put(segments[0]);
		fc.put(segments[2]);
		testLast(segments[0], segments[3]);
		testLast(segments[0], segments[3]); // should be same, if persistent server will get back same data
		_handle.get(new Interest(segment_names[0]), 0);
		
		System.out.println("Testing \"waitForPutDrain\"");
		try {
			// can't call waitForPutDrain directly; call it via afterClose
			fc.afterClose();
		} catch (IOException ioe) {
			Assert.fail("WaitforPutDrain threw unexpected exception");
		}
		fc.put(obj1);
		try {
			// can't call waitForPutDrain directly; call it via afterClose
			fc.afterClose(); // with a flow server, shouldn't throw waitForPutDrain. We don't
				// care if anyone takes stuff
		} catch (IOException ioe) {
			Assert.fail("WaitforPutDrain threw unexpected exception");
		}
	}
	
	@Test
	public void testHighwaterWait() throws Exception {
		
		// Test that put over highwater fails with nothing draining
		// the buffer
		normalReset(name1);
		fc.setCapacity(4);
		fc.put(segments[0]);
		fc.put(segments[1]);
		fc.put(segments[2]);
		fc.put(segments[3]);
		try {
			fc.put(segments[4]);
			Assert.fail("Put over highwater mark succeeded");
		} catch (IOException ioe) {}
		
		// Test that put over highwater doesn't succeed when persistent buffer is
		// drained
		normalReset(name1);
		fc.setCapacity(4);
		fc.put(segments[0]);
		fc.put(segments[1]);
		fc.put(segments[2]);

		ThreadAssertionRunner tar = new ThreadAssertionRunner(new HighWaterHelper());
		tar.start();
		try {
			fc.put(segments[3]);
			fc.put(segments[4]);
			Assert.fail("Attempt to put over capacity in non-draining FC succeeded.");
		} catch (IOException ioe) {}
		tar.join();
	}
	
	protected void normalReset(ContentName n) throws IOException {
		_handle.reset();
		interestList.clear();
		fc = new CCNFlowServer(n, _capacity, true, _handle);
		fc.setTimeout(100);
	}
}
