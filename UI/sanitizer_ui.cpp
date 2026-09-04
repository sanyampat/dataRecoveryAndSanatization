#include <pybind11/pybind11.h>

#include <pybind11/stl.h>
 
#include "include/DataSanitizer.h"
 
namespace py = pybind11;
 
PYBIND11_MODULE(cpp_sanitizer, m) {

    m.doc() = "C++ Data Sanitisation Engine Pybind11 Bindings";
 
    py::class_<DataSanitizer>(m, "DataSanitizer")

        .def(py::init<>())

        .def("sanitizeSector", &DataSanitizer::sanitizeSector, 

             py::arg("targetPath"), 

             py::arg("passes") = 3)

        .def("zeroFill", &DataSanitizer::zeroFill, 

             py::arg("targetPath"));

}
 
