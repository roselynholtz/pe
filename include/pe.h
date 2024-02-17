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
		uintptr_t m_image_address;

		// dos header.
		IMAGE_DOS_HEADER* m_dos_header;

		// are we a pe file?
		bool m_pe;

		// retrieves all header pointers.
		void populate_headers( )
		{
			// dos header starts at the first byte and spans 64 bytes.
			m_dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( m_image_address );

			// pe files are identified by the ascii string
			// "MZ" or in hex: 4D5A
			// byte order is flipped (little-endian)
			// so "MZ" becomes "ZM" (5A4D).
			m_pe = m_dos_header->e_magic == 0x5A4D;

			// we aren't a pe file, don't bother.
			if ( !m_pe )
				return;
		}
	public:
		file( const std::vector< uint8_t >& image_data )
		{
			m_image_data = image_data;

			// set our address in memory.
			m_image_address = reinterpret_cast< uintptr_t >( m_image_data.data( ) );

			// populate our headers.
			populate_headers( );

			// we aren't a pe file, don't bother.
			if ( !m_pe )
				return;
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

		// true if 'm_image_data' is not empty and this is a pe file.
		bool good( )
		{
			return !m_image_data.empty( ) && m_pe;
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

			std::cout << "file loaded" << std::endl;

			if ( !m_pe )
			{
				std::cout << "file is not in pe format" << std::endl;
				return;
			}

			std::cout << "file is in pe format" << std::endl;

			// headers.
			// we skip dos header here since it is not useful.
		}
	#endif
	};
}