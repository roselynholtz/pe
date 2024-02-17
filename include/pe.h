#pragma once

// verbose logging.
//#define PE_VERBOSE

#include <Windows.h>
#include <vector>

#ifdef PE_VERBOSE
#include <iostream>
#endif

namespace pe
{
	// sections contained within a pe file.
	class file_section
	{
	public:

	};

	// basic PE file.
	class file
	{
		// raw image data.
		std::vector< uint8_t > m_image_data;

		// address of the first byte of our image in memory.
		uintptr_t m_image_address = 0x0;

		// dos header.
		IMAGE_DOS_HEADER* m_dos_header;

		// retrieves all header pointers.
		void populate_headers( )
		{
			// dos header starts at the first byte and spans 64 bytes.
			m_dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( m_image_address );
		}
	public:
		file( const std::vector< uint8_t >& image_data )
		{
			m_image_data = image_data;

			// set our address in memory.
			m_image_address = reinterpret_cast< uintptr_t >( m_image_data.data( ) );

			// populate our headers.
			populate_headers( );
		}

		// sets the 'm_image_data' member.
		void set_image_data( const std::vector< uint8_t >& image_data )
		{
			m_image_data = image_data;
		}

		// returns a read only version of the 'm_image_data' member.
		const std::vector< uint8_t >& get_image_data( ) const
		{
			return m_image_data;
		}

		// clears all data about this file from memory.
		void scrub( )
		{
			// clear image data first.
			m_image_data.clear( );

			// reset our image address.
			m_image_address = 0x0;
		}

		// true if 'm_image_data' is not empty.
		bool good( )
		{
			return !m_image_data.empty( );
		}

	#ifdef PE_VERBOSE
		// spews all debug data about the file.
		void spew( )
		{
			std::cout << "----------------------------------" << std::endl;
			std::cout << "|            pe file             |" << std::endl;
			std::cout << "----------------------------------" << std::endl << std::endl;

			// we don't have a valid file.
			if ( !good( ) )
			{
				std::cout << "no valid file loaded" << std::endl;
				return;
			}

			// headers.
			// we skip dos header here since it is not useful.
		}
	#endif
	};
}