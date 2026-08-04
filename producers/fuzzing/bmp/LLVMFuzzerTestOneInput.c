/*
 * LLVMFuzzerTestOneInput.c
 *
 * Host-based (off-target) libFuzzer + AddressSanitizer harness for the edk2
 * BMP -> GOP BLT converter.
 *
 * TARGET FUNCTION: TranslateBmpToGopBlt()
 * EDK2 SOURCE:     MdeModulePkg/Library/BaseBmpSupportLib/BmpSupportLib.c
 *                  (lines 78-434 of that file — the RETURN_STATUS
 *                   TranslateBmpToGopBlt(...) definition)
 *
 * The function body below is COPIED VERBATIM from that source file so that the
 * fuzzed logic is byte-identical to the code that ships on target. Everything
 * it depends on (types, macros, SafeIntLib, AllocatePool/FreePool, DEBUG) is
 * supplied by shim.h. The edk2 tree itself is NOT modified and NOT built.
 *
 * The only edited line vs. upstream: the historical companion routine
 * TranslateGopBltToBmp() is omitted (it is a separate, non-attacker-reachable
 * encoder), and the two edk2 #include lines are replaced by #include "shim.h".
 *
 * Attack surface: BMP width/height/bit-per-pixel come straight from attacker-
 * controlled bytes and feed width*height*sizeof(pixel) allocation math plus a
 * per-row Image[] / BmpColorMap[] walk. See README.md for the bug classes.
 */

#include "shim.h"
#include <string.h>

/* ======================================================================== *
 * BEGIN verbatim copy: BmpSupportLib.c lines 78-434
 * ======================================================================== */
RETURN_STATUS
EFIAPI
TranslateBmpToGopBlt (
  IN     VOID                           *BmpImage,
  IN     UINTN                          BmpImageSize,
  IN OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  **GopBlt,
  IN OUT UINTN                          *GopBltSize,
  OUT    UINTN                          *PixelHeight,
  OUT    UINTN                          *PixelWidth
  )
{
  UINT8                          *Image;
  UINT8                          *ImageHeader;
  BMP_IMAGE_HEADER               *BmpHeader;
  BMP_COLOR_MAP                  *BmpColorMap;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BltBuffer;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Blt;
  UINT32                         BltBufferSize;
  UINTN                          Index;
  UINTN                          Height;
  UINTN                          Width;
  UINTN                          ImageIndex;
  UINT32                         DataSizePerLine;
  BOOLEAN                        IsAllocated;
  UINT32                         ColorMapNum;
  RETURN_STATUS                  Status;
  UINT32                         DataSize;
  UINT32                         Temp;

  if ((BmpImage == NULL) || (GopBlt == NULL) || (GopBltSize == NULL)) {
    return RETURN_INVALID_PARAMETER;
  }

  if ((PixelHeight == NULL) || (PixelWidth == NULL)) {
    return RETURN_INVALID_PARAMETER;
  }

  if (BmpImageSize < sizeof (BMP_IMAGE_HEADER)) {
    DEBUG ((DEBUG_ERROR, "TranslateBmpToGopBlt: BmpImageSize too small\n"));
    return RETURN_UNSUPPORTED;
  }

  BmpHeader = (BMP_IMAGE_HEADER *)BmpImage;

  if ((BmpHeader->CharB != 'B') || (BmpHeader->CharM != 'M')) {
    DEBUG ((DEBUG_ERROR, "TranslateBmpToGopBlt: BmpHeader->Char fields incorrect\n"));
    return RETURN_UNSUPPORTED;
  }

  //
  // Doesn't support compress.
  //
  if (BmpHeader->CompressionType != 0) {
    DEBUG ((DEBUG_ERROR, "TranslateBmpToGopBlt: Compression Type unsupported.\n"));
    return RETURN_UNSUPPORTED;
  }

  if ((BmpHeader->PixelHeight == 0) || (BmpHeader->PixelWidth == 0)) {
    DEBUG ((DEBUG_ERROR, "TranslateBmpToGopBlt: BmpHeader->PixelHeight or BmpHeader->PixelWidth is 0.\n"));
    return RETURN_UNSUPPORTED;
  }

  //
  // Only support BITMAPINFOHEADER format.
  // BITMAPFILEHEADER + BITMAPINFOHEADER = BMP_IMAGE_HEADER
  //
  if (BmpHeader->HeaderSize != sizeof (BMP_IMAGE_HEADER) - OFFSET_OF (BMP_IMAGE_HEADER, HeaderSize)) {
    DEBUG ((
      DEBUG_ERROR,
      "TranslateBmpToGopBlt: BmpHeader->Headership is not as expected.  Headersize is 0x%x\n",
      BmpHeader->HeaderSize
      ));
    return RETURN_UNSUPPORTED;
  }

  //
  // The data size in each line must be 4 byte alignment.
  //
  Status = SafeUint32Mult (
             BmpHeader->PixelWidth,
             BmpHeader->BitPerPixel,
             &DataSizePerLine
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "TranslateBmpToGopBlt: invalid BmpImage... PixelWidth:0x%x BitPerPixel:0x%x\n",
      BmpHeader->PixelWidth,
      BmpHeader->BitPerPixel
      ));
    return RETURN_UNSUPPORTED;
  }

  Status = SafeUint32Add (DataSizePerLine, 31, &DataSizePerLine);
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "TranslateBmpToGopBlt: invalid BmpImage... DataSizePerLine:0x%x\n",
      DataSizePerLine
      ));

    return RETURN_UNSUPPORTED;
  }

  DataSizePerLine = (DataSizePerLine >> 3) &(~0x3);
  Status          = SafeUint32Mult (
                      DataSizePerLine,
                      BmpHeader->PixelHeight,
                      &BltBufferSize
                      );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "TranslateBmpToGopBlt: invalid BmpImage... DataSizePerLine:0x%x PixelHeight:0x%x\n",
      DataSizePerLine,
      BmpHeader->PixelHeight
      ));

    return RETURN_UNSUPPORTED;
  }

  Status = SafeUint32Mult (
             BmpHeader->PixelHeight,
             DataSizePerLine,
             &DataSize
             );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "TranslateBmpToGopBlt: invalid BmpImage... PixelHeight:0x%x DataSizePerLine:0x%x\n",
      BmpHeader->PixelHeight,
      DataSizePerLine
      ));

    return RETURN_UNSUPPORTED;
  }

  if ((BmpHeader->Size != BmpImageSize) ||
      (BmpHeader->Size < BmpHeader->ImageOffset) ||
      (BmpHeader->Size - BmpHeader->ImageOffset != DataSize))
  {
    DEBUG ((DEBUG_ERROR, "TranslateBmpToGopBlt: invalid BmpImage... \n"));
    DEBUG ((DEBUG_ERROR, "   BmpHeader->Size: 0x%x\n", BmpHeader->Size));
    DEBUG ((DEBUG_ERROR, "   BmpHeader->ImageOffset: 0x%x\n", BmpHeader->ImageOffset));
    DEBUG ((DEBUG_ERROR, "   BmpImageSize: 0x%lx\n", (UINTN)BmpImageSize));
    DEBUG ((DEBUG_ERROR, "   DataSize: 0x%lx\n", (UINTN)DataSize));

    return RETURN_UNSUPPORTED;
  }

  //
  // Calculate Color Map offset in the image.
  //
  Image       = BmpImage;
  BmpColorMap = (BMP_COLOR_MAP *)(Image + sizeof (BMP_IMAGE_HEADER));
  if (BmpHeader->ImageOffset < sizeof (BMP_IMAGE_HEADER)) {
    return RETURN_UNSUPPORTED;
  }

  if (BmpHeader->ImageOffset > sizeof (BMP_IMAGE_HEADER)) {
    switch (BmpHeader->BitPerPixel) {
      case 1:
        ColorMapNum = 2;
        break;
      case 4:
        ColorMapNum = 16;
        break;
      case 8:
        ColorMapNum = 256;
        break;
      default:
        ColorMapNum = 0;
        break;
    }

    //
    // BMP file may has padding data between the bmp header section and the
    // bmp data section.
    //
    if (BmpHeader->ImageOffset - sizeof (BMP_IMAGE_HEADER) < sizeof (BMP_COLOR_MAP) * ColorMapNum) {
      return RETURN_UNSUPPORTED;
    }
  }

  //
  // Calculate graphics image data address in the image
  //
  Image       = ((UINT8 *)BmpImage) + BmpHeader->ImageOffset;
  ImageHeader = Image;

  //
  // Calculate the BltBuffer needed size.
  //
  Status = SafeUint32Mult (
             BmpHeader->PixelWidth,
             BmpHeader->PixelHeight,
             &BltBufferSize
             );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "TranslateBmpToGopBlt: invalid BltBuffer needed size... PixelWidth:0x%x PixelHeight:0x%x\n",
      BmpHeader->PixelWidth,
      BmpHeader->PixelHeight
      ));

    return RETURN_UNSUPPORTED;
  }

  Temp   = BltBufferSize;
  Status = SafeUint32Mult (
             BltBufferSize,
             sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL),
             &BltBufferSize
             );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "TranslateBmpToGopBlt: invalid BltBuffer needed size... PixelWidth x PixelHeight:0x%x struct size:0x%x\n",
      Temp,
      sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
      ));

    return RETURN_UNSUPPORTED;
  }

  IsAllocated = FALSE;
  if (*GopBlt == NULL) {
    //
    // GopBlt is not allocated by caller.
    //
    DEBUG ((DEBUG_INFO, "Bmp Support: Allocating 0x%X bytes of memory\n", BltBufferSize));
    *GopBltSize = (UINTN)BltBufferSize;
    *GopBlt     = AllocatePool (*GopBltSize);
    IsAllocated = TRUE;
    if (*GopBlt == NULL) {
      return RETURN_OUT_OF_RESOURCES;
    }
  } else {
    //
    // GopBlt has been allocated by caller.
    //
    if (*GopBltSize < (UINTN)BltBufferSize) {
      *GopBltSize = (UINTN)BltBufferSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
  }

  *PixelWidth  = BmpHeader->PixelWidth;
  *PixelHeight = BmpHeader->PixelHeight;
  DEBUG ((DEBUG_INFO, "BmpHeader->ImageOffset 0x%X\n", BmpHeader->ImageOffset));
  DEBUG ((DEBUG_INFO, "BmpHeader->PixelWidth 0x%X\n", BmpHeader->PixelWidth));
  DEBUG ((DEBUG_INFO, "BmpHeader->PixelHeight 0x%X\n", BmpHeader->PixelHeight));
  DEBUG ((DEBUG_INFO, "BmpHeader->BitPerPixel 0x%X\n", BmpHeader->BitPerPixel));
  DEBUG ((DEBUG_INFO, "BmpHeader->ImageSize 0x%X\n", BmpHeader->ImageSize));
  DEBUG ((DEBUG_INFO, "BmpHeader->HeaderSize 0x%X\n", BmpHeader->HeaderSize));
  DEBUG ((DEBUG_INFO, "BmpHeader->Size 0x%X\n", BmpHeader->Size));

  //
  // Translate image from BMP to Blt buffer format
  //
  BltBuffer = *GopBlt;
  for (Height = 0; Height < BmpHeader->PixelHeight; Height++) {
    Blt = &BltBuffer[(BmpHeader->PixelHeight - Height - 1) * BmpHeader->PixelWidth];
    for (Width = 0; Width < BmpHeader->PixelWidth; Width++, Image++, Blt++) {
      switch (BmpHeader->BitPerPixel) {
        case 1:
          //
          // Translate 1-bit (2 colors) BMP to 24-bit color
          //
          for (Index = 0; Index < 8 && Width < BmpHeader->PixelWidth; Index++) {
            Blt->Red   = BmpColorMap[((*Image) >> (7 - Index)) & 0x1].Red;
            Blt->Green = BmpColorMap[((*Image) >> (7 - Index)) & 0x1].Green;
            Blt->Blue  = BmpColorMap[((*Image) >> (7 - Index)) & 0x1].Blue;
            Blt++;
            Width++;
          }

          Blt--;
          Width--;
          break;

        case 4:
          //
          // Translate 4-bit (16 colors) BMP Palette to 24-bit color
          //
          Index      = (*Image) >> 4;
          Blt->Red   = BmpColorMap[Index].Red;
          Blt->Green = BmpColorMap[Index].Green;
          Blt->Blue  = BmpColorMap[Index].Blue;
          if (Width < (BmpHeader->PixelWidth - 1)) {
            Blt++;
            Width++;
            Index      = (*Image) & 0x0f;
            Blt->Red   = BmpColorMap[Index].Red;
            Blt->Green = BmpColorMap[Index].Green;
            Blt->Blue  = BmpColorMap[Index].Blue;
          }

          break;

        case 8:
          //
          // Translate 8-bit (256 colors) BMP Palette to 24-bit color
          //
          Blt->Red   = BmpColorMap[*Image].Red;
          Blt->Green = BmpColorMap[*Image].Green;
          Blt->Blue  = BmpColorMap[*Image].Blue;
          break;

        case 24:
          //
          // It is 24-bit BMP.
          //
          Blt->Blue  = *Image++;
          Blt->Green = *Image++;
          Blt->Red   = *Image;
          break;

        case 32:
          //
          // Conver 32 bit to 24bit bmp - just ignore the final byte of each pixel
          Blt->Blue  = *Image++;
          Blt->Green = *Image++;
          Blt->Red   = *Image++;
          break;

        default:
          //
          // Other bit format BMP is not supported.
          //
          if (IsAllocated) {
            FreePool (*GopBlt);
            *GopBlt = NULL;
          }

          DEBUG ((DEBUG_ERROR, "Bmp Bit format not supported.  0x%X\n", BmpHeader->BitPerPixel));
          return RETURN_UNSUPPORTED;
          break;
      }
    }

    ImageIndex = (UINTN)Image - (UINTN)ImageHeader;
    if ((ImageIndex % 4) != 0) {
      //
      // Bmp Image starts each row on a 32-bit boundary!
      //
      Image = Image + (4 - (ImageIndex % 4));
    }
  }

  return RETURN_SUCCESS;
}
/* ======================================================================== *
 * END verbatim copy
 * ======================================================================== */

/*
 * libFuzzer entry point.
 *
 * We copy the fuzzer-provided input into an EXACT-SIZE heap allocation before
 * handing it to the target. That is deliberate: AddressSanitizer places
 * redzones immediately after that allocation, so any read the target makes
 * past BmpImageSize (the classic over-read when header-declared geometry does
 * not match the buffer) is reported as a heap-buffer-overflow instead of
 * silently succeeding against slack in a static buffer.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *Data, size_t Size)
{
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *GopBlt      = NULL; /* NULL => target allocates */
  UINTN                          GopBltSize   = 0;
  UINTN                          PixelHeight  = 0;
  UINTN                          PixelWidth   = 0;
  RETURN_STATUS                  Status;
  uint8_t                        *Buf;

  /* malloc(0) is implementation-defined; give ASAN a real 1-byte object so the
   * NULL/too-small early-return paths still exercise cleanly. */
  Buf = (uint8_t *)malloc (Size ? Size : 1);
  if (Buf == NULL) {
    return 0;
  }
  if (Size) {
    memcpy (Buf, Data, Size);
  }

  Status = TranslateBmpToGopBlt (
             Buf,
             (UINTN)Size,
             &GopBlt,
             &GopBltSize,
             &PixelHeight,
             &PixelWidth
             );

  /* On success the target allocated GopBlt via AllocatePool()==malloc(); free
   * it. On failure it either never allocated or freed+NULLed it internally. */
  if (!EFI_ERROR (Status) && (GopBlt != NULL)) {
    FreePool (GopBlt);
  }

  free (Buf);
  return 0;
}
