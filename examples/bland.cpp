#define PE_VERBOSE
#include <pe/include/pe.h>
#include <fstream>
#include <iostream>

int main( int argc, char* argv[ ] )
{
	// user didn't provide a valid file.
	if ( argc != 2 )
	{
		std::cout << "usage: " << argv[ 0 ] << " <file_path>" << std::endl;
		return 1;
	}

	// contains our raw file data.
	std::vector< uint8_t > image_data;

	// open the file on disk.
	std::ifstream file( std::string( argv[ 1 ] ), std::ios::binary );

	// something went while opening this file (invalid permissions maybe?)
	if ( !file.is_open( ) )
	{
		std::cout << "failed to open file" << std::endl;
		return 2;
	}

	// seek to the end of the file.
	file.seekg( 0, std::ios::end );

	// retrieve the size of the file.
	size_t file_size = file.tellg( );

	// resize our vector to our file size.
	image_data.resize( file_size );

	// read the file data directory into our vector.
	file.read( reinterpret_cast< char* >( image_data.data( ) ), file_size );

	// close our file.
	file.close( );

	// create our pe file instance.
	pe::file pe_file = pe::file( image_data );

	// something went wrong with initialization.
	if ( !pe_file.good( ) )
	{
		std::cout << "pe::file initialization failed" << std::endl;
		return 3;
	}

	// spew debug information about this file.
	pe_file.spew( );

	// clear our image data.
	image_data.clear( );

	// scrub our pe::file instance from memory.
	pe_file.scrub( );

	return 0;
}