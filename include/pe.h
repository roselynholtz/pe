#pragma once

#include <Windows.h>
#include <vector>

namespace pe
{
	// basic PE image.
	class image
	{
		// raw image data.
		std::vector< uint8_t > m_image_data;

		// address of the first byte of our image in memory.
		uintptr_t m_image_address;

		// dos header.
		IMAGE_DOS_HEADER* m_dos_header;

		// file header.
		IMAGE_FILE_HEADER* m_file_header;

		// optional header.
		IMAGE_OPTIONAL_HEADER* m_optional_header;

		// retrieves all header pointers.
		void populate_headers( )
		{
			// dos header starts at the first byte and spans 64 bytes.
			m_dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( m_image_address );

			// IMAGE_DOS_HEADER::e_lfanew contains the offset of nt headers from our image base.
			IMAGE_NT_HEADERS* nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( m_image_address + m_dos_header->e_lfanew );

			// invalid nt headers, don't bother.
			if ( !nt_headers )
				return;

			// file header.
			m_file_header = &nt_headers->FileHeader;

			// optional header.
			m_optional_header = &nt_headers->OptionalHeader;
		}
	public:
		image( const std::vector< uint8_t >& image_data ) : m_image_data( image_data ), m_image_address( reinterpret_cast< uintptr_t >( m_image_data.data( ) ) )
		{
			// populate our headers.
			populate_headers( );

			// initial setup failed, don't bother.
			if ( !good( ) )
				return;
		}

		// clears all data about this file from memory.
		void clear( )
		{
			// clear image data first.
			m_image_data.clear( );

			// reset our image address.
			m_image_address = 0x0;
		}

		// true if the image seems to have no issues.
		// this is not extensive.
		bool good( ) const
		{
			// bad image data.
			if ( m_image_data.empty( ) )
				return false;

			// not in pe format.
			// pe files are identified by the ascii string
			// "MZ" or in hex: 4D5A
			// byte order is flipped (little-endian)
			// so "MZ" becomes "ZM" (5A4D).
			if ( m_dos_header->e_magic != 0x5A4D )
				return false;

			// invalid headers.
			if ( !m_file_header || !m_optional_header )
				return false;

			return true;
		}

		// dos header for this image.
		const IMAGE_DOS_HEADER* dos_header( ) const
		{
			return m_dos_header;
		}

		// file header for this image.
		const IMAGE_FILE_HEADER* file_header( ) const
		{
			return m_file_header;
		}

		// optional header for this image.
		const IMAGE_OPTIONAL_HEADER* optional_header( ) const
		{
			return m_optional_header;
		}
	};
}