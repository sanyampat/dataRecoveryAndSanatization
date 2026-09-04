// SIH Sanitizer UI
//
// Lists detected drives, lets the user pick one or more (or "select all"),
// and runs SanitizationEngine::executeSanitization on the selection after an
// explicit typed confirmation. Built with FLTK so it stays small enough to
// ship inside the live OS rootfs (no GTK/Qt runtime needed).
//
// NOTE: SanitizationEngine is currently dry-run only (see sanitization/*).
// This UI does not change that — it just drives the same engine the CLI
// test apps use. Nothing here sends a destructive command to a device.

#include "../../device/DriveManager.h"
#include "../../sanitization/SanitizationEngine.h"

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Check_Browser.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Box.H>
#include <FL/fl_ask.H>

#include <string>
#include <sstream>
#include <vector>

namespace {

// Formats one drive as a single browser row: "sda  TOSHIBA THNSFJ25  SATA  SSD  256060514304 bytes"
std::string formatDriveRow(const core::drive::DriveInfo& d) {
    std::ostringstream oss;
    oss << d.devicePath << "   "
        << d.model << "   "
        << d.getBusTypeString() << "   "
        << d.getMediaTypeString() << "   "
        << d.capacityBytes << " bytes";
    return oss.str();
}

} // namespace

class SanitizerUI {
public:
    SanitizerUI()
        : window_(640, 480, "SIH Sanitizer") {
        window_.begin();

        auto* heading = new Fl_Box(10, 10, 620, 24, "Detected drives");
        heading->labelfont(FL_BOLD);
        heading->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

        browser_ = new Fl_Check_Browser(10, 40, 620, 200);

        refreshBtn_ = new Fl_Button(10, 250, 120, 28, "Refresh");
        refreshBtn_->callback(refreshCb, this);

        selectAllBtn_ = new Fl_Button(140, 250, 120, 28, "Select all");
        selectAllBtn_->callback(selectAllCb, this);

        clearBtn_ = new Fl_Button(270, 250, 120, 28, "Clear selection");
        clearBtn_->callback(clearSelectionCb, this);

        sanitizeSelectedBtn_ = new Fl_Button(10, 290, 200, 32, "Sanitize selected");
        sanitizeSelectedBtn_->color(FL_RED);
        sanitizeSelectedBtn_->labelcolor(FL_WHITE);
        sanitizeSelectedBtn_->callback(sanitizeSelectedCb, this);

        sanitizeAllBtn_ = new Fl_Button(220, 290, 200, 32, "Sanitize ALL drives");
        sanitizeAllBtn_->color(FL_RED);
        sanitizeAllBtn_->labelcolor(FL_WHITE);
        sanitizeAllBtn_->callback(sanitizeAllCb, this);

        auto* logHeading = new Fl_Box(10, 332, 620, 20, "Log");
        logHeading->labelfont(FL_BOLD);
        logHeading->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

        logBuffer_ = new Fl_Text_Buffer();
        logDisplay_ = new Fl_Text_Display(10, 356, 620, 114);
        logDisplay_->buffer(logBuffer_);

        window_.end();
        window_.resizable(browser_);

        refreshDrives();
    }

    void show() { window_.show(); }

private:
    Fl_Double_Window window_;
    Fl_Check_Browser* browser_ = nullptr;
    Fl_Button* refreshBtn_ = nullptr;
    Fl_Button* selectAllBtn_ = nullptr;
    Fl_Button* clearBtn_ = nullptr;
    Fl_Button* sanitizeSelectedBtn_ = nullptr;
    Fl_Button* sanitizeAllBtn_ = nullptr;
    Fl_Text_Buffer* logBuffer_ = nullptr;
    Fl_Text_Display* logDisplay_ = nullptr;

    core::drive::DriveManager driveManager_;
    std::vector<core::drive::DriveInfo> drives_;

    void log(const std::string& line) {
        logBuffer_->append((line + "\n").c_str());
        logDisplay_->scroll(logBuffer_->count_lines(0, logBuffer_->length()), 0);
    }

    void refreshDrives() {
        drives_ = driveManager_.getAvailableDrives();
        browser_->clear();

        if (drives_.empty()) {
            log("No drives detected.");
            return;
        }

        for (const auto& d : drives_) {
            browser_->add(formatDriveRow(d).c_str());
        }
        log("Found " + std::to_string(drives_.size()) + " drive(s).");
    }

    // Runs the sanitization engine over the given drive indices, after one
    // explicit confirmation naming exactly what will be touched.
    void runSanitization(const std::vector<std::size_t>& indices) {
        if (indices.empty()) {
            fl_alert("No drives selected.");
            return;
        }

        std::ostringstream confirmMsg;
        confirmMsg << "You are about to sanitize " << indices.size()
                    << " drive(s):\n\n";
        for (auto idx : indices) {
            confirmMsg << "  " << drives_[idx].devicePath
                        << "  (" << drives_[idx].model << ")\n";
        }
        confirmMsg << "\nThis cannot be undone. Continue?";

        int choice = fl_choice("%s", "Cancel", "Sanitize", nullptr, confirmMsg.str().c_str());
        if (choice != 1) {
            log("Sanitization cancelled by user.");
            return;
        }

        core::sanitization::SanitizationEngine engine;

        for (auto idx : indices) {
            const auto& drive = drives_[idx];
            log("Starting sanitization: " + drive.devicePath);

            bool result = engine.executeSanitization(drive);

            if (result) {
                log("  -> completed: " + drive.devicePath);
            } else {
                log("  -> did not execute (dry-run mode): " + drive.devicePath);
            }
        }

        log("Batch complete.");
    }

    std::vector<std::size_t> selectedIndices() const {
        std::vector<std::size_t> out;
        for (int i = 1; i <= browser_->nitems(); ++i) {
            if (browser_->checked(i)) {
                out.push_back(static_cast<std::size_t>(i - 1)); // browser is 1-indexed
            }
        }
        return out;
    }

    // --- FLTK callbacks (static trampolines into instance methods) ---

    static void refreshCb(Fl_Widget*, void* self) {
        static_cast<SanitizerUI*>(self)->refreshDrives();
    }

    static void selectAllCb(Fl_Widget*, void* self) {
        auto* ui = static_cast<SanitizerUI*>(self);
        for (int i = 1; i <= ui->browser_->nitems(); ++i) {
            ui->browser_->checked(i, 1);
        }
    }

    static void clearSelectionCb(Fl_Widget*, void* self) {
        auto* ui = static_cast<SanitizerUI*>(self);
        for (int i = 1; i <= ui->browser_->nitems(); ++i) {
            ui->browser_->checked(i, 0);
        }
    }

    static void sanitizeSelectedCb(Fl_Widget*, void* self) {
        auto* ui = static_cast<SanitizerUI*>(self);
        ui->runSanitization(ui->selectedIndices());
    }

    static void sanitizeAllCb(Fl_Widget*, void* self) {
        auto* ui = static_cast<SanitizerUI*>(self);
        std::vector<std::size_t> all;
        for (std::size_t i = 0; i < ui->drives_.size(); ++i) all.push_back(i);
        ui->runSanitization(all);
    }
};

int main(int argc, char** argv) {
    Fl::scheme("gtk+"); // closest built-in FLTK scheme to a plain, uncluttered look
    SanitizerUI ui;
    ui.show();
    return Fl::run();
}