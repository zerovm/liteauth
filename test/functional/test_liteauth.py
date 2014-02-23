import unittest
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.wait import WebDriverWait


class TestLiteauth(unittest.TestCase):

    def setUp(self):
        self.browser = webdriver.Firefox()

    def tearDown(self):
        pass

    def test_login(self):
        self.browser.get('https://z.zerovm.org/login/google/?state=/js')
        email = self.browser.find_element_by_id('Email')
        self.assertIsNotNone(email)
        email.send_keys('azerovm@gmail.com')
        password = self.browser.find_element_by_id('Passwd')
        self.assertIsNotNone(password)
        password.send_keys('DazoMazo' + Keys.RETURN)

        try:
            approve = WebDriverWait(self.browser, 20).until(
                expected_conditions.element_to_be_clickable(
                    (By.ID, 'submit_approve_access')))
            # approve = self.browser.find_element_by_id('submit_approve_access')
            self.assertIsNotNone(approve)
            approve.click()
        except TimeoutException:
            pass