import unittest
import arp_spoofing


class ArpSpoofingTestCase(unittest.TestCase):
    def setUp(self):
        #self.args1 = (3, 2)

    def tearDown(self):
        #self.args1 = None

    #def test_plus_a_num(self):
        #expected = 5
        #result = arp_spoofing.PlusNumFunc(*self.args1)
        #self.assertEqual(expected, result)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(ArpSpoofingTestCase)
    unittest.main()