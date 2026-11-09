import unittest
import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
import fedora_crash_doctor

class GUISmokeTest(unittest.TestCase):
    def test_gui_starts_and_closes_cleanly(self):
        # We need an application instance
        app = QApplication.instance()
        if not app:
            app = QApplication(sys.argv)
            
        try:
            window = fedora_crash_doctor.MainWindow()
            
            # Show the window briefly
            window.show()
            
            # Process events
            app.processEvents()
            
            # Test that we can switch to the System History and RuneScape Doctor tabs
            # We don't have to literally switch, just making sure they are built
            self.assertIsNotNone(window.history_tree)
            self.assertIsNotNone(window.rs_detail_browser)
            self.assertIsNotNone(window.rs_tab_diagnose_btn)
            
            # Setup a timer to close the window after processing
            def close_window():
                window.close()
                app.quit()
                
            QTimer.singleShot(100, close_window)
            app.exec()
            
            # If we reached here without exception, it's successful
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"GUI smoke test failed with exception: {e}")

if __name__ == "__main__":
    unittest.main()
