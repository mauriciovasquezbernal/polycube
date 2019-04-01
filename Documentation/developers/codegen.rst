Polycube Automatic Code Generation Tools
========================================

Generating a service stub
-------------------------

``pyang`` and ``swagger-codegen`` are used to generate a service stub using the YANG datamodel.
The former parses the YANG file and creates an intermediate JSON that is compliant with the `OpenAPI specifications <https://swagger.io/specification/>`_; the second starts from the latter file and creates a C++ code skeleton that actually implements the service. Among the services that are automatically provided, the C++ skeleton handles the case in which a complex object is requested, such as the entire configuration of the service, which is returned by disaggregating the big request into a set of smaller requests for each *leaf* object.
Hence, this leaves to the programmer only the responsibility to implement the interaction with *leaf* objects.

The easiest way to generate a stub is to use the `polycubenetwork/polycube-codegen` docker image.
This contains ``pyang``, ``swagger-codegen`` and a script to invoke them.

In order to run the image, it is needed to mount a volume into ``/polycube-base-datamodels`` where the base datamodels are located on the host (by default ``/usr/local/include/polycube/datamodel-common/``), it is also needed to mount a volume to share the input yang model and the output folder.

::

  export POLYCUBE_BASEMODELS=<path to base models usually /usr/local/include/polycube/datamodel-common/>
  docker pull polycubenetwork/polycube-codegen
   docker run -it \
    -v $POLYCUBE_BASEMODELS:/polycube-base-datamodels \ # mount base models folder
    -v <input yang>:/input \ # mount folder with input yang
    -v <output folder in host>:/output
    polycubenetwork/polycube-codegen
    -i /input/<yang datamodel> # yang input file, notice that it is relative to the volume
    -o /output/<output folder> # destination folder, again related to the volume

Code Structure
**************

- **src/api/{service-name}Api.[h,cpp]** and **src/api/{service-name}ApiImpl.[h,cpp]**: Implements the shared library entry points to handle the different request for the rest API endpoints. The developers does not have to modify it.
- **src/interface/**: This folder contains one pure virtual class for each object used in the control API. Each class contains the methods that must be implemented in each object class.
- **src/serializer/**: This folder contains one JSON object class for each object used in the control API. These classes are used to performs the marshalling/unmarshalling operations.
- **src/{object-name}.h**: One header file for each object used in the control API. These classes implement the corresponding object interface stored in the `src/interface` folder.
- **src/{object-name}.cpp**: These files contain the getter and setter methods, constructor and destructor and finally some methods to handle the object life cycle such as create, delete, replace, update and read. Some methods contain a basic implementation, others instead have to be implemented.
- **src/{service-name}_dp.c**: Contains the datapath code for the service.
- **src/{service-name]-lib.cpp**: Is used to compile the service as shared library.
- **.swagger-codegen-ignore**: This file is used to prevent files from being overwritten by the generator if a re-generation is performed.

Updating an existing service stub
*********************************

This step is required if the service skeleton already exists and the programmer has to update the YANG model with new features.
This procedure avoids to overwrite all the source code already generated, by adopting an incremental approach that minimizes the changes in the existing code to the developer.

Starting from the generated classes, the developer only has to modify the ``src/{object-name}.h``, ``src/{object-name}.cpp`` and ``src/{service-name}_dp.c`` files.

The ``src/{object-name}.cpp`` files contain the stub for the methods that the developer has to modify.
Some of them have a basic implementation and the developer is suggested to improve it, others present only the stub.
The developer has to implement constructor and destructor for each object.
Moreover in these classes the developer has to implement the getter and setter methods for each parameter contained in the object.

In order to achieve the target, the developer is free to add fields and methods to these classes and also add other classes if necessary.

If the developer has to re-generate the service stub (because he modified something in datamodel), we suggest to avoid the re-generation of some files by properly modifying the `.swagger-codegen-ignore` file. All the files are considered in the `src/` folder (except for the files in `src/api/` folder). To avoid a file re-generation the developer has to write the file name in the `.swagger-codegen-ignore` file. If the file name is preceded by the `!` character or it is not present, the file will be overwritten. For default the `.swagger-codegen-ignore` avoids the re-generation of all the files that the developer has to modify (``src/{object-name}.h``, ``src/{object-name}.cpp``  and `src/{service-name}_dp.c`` files).

**Important**: do not remove the line ``.swagger-codegen-ignore`` present in the ``.swagger-codegen-ignore`` file because otherwise this file will be overwritten and this causes the loss of previous modifications to the file.



