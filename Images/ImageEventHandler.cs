#region "copyright"

/*
    Copyright (c) 2024 Dale Ghent <daleg@elemental.org>

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/
*/

#endregion "copyright"

using NINA.Core.Enum;
using NINA.Core.Utility;
using NINA.Image.Interfaces;
using NINA.Profile.Interfaces;
using NINA.WPF.Base.Interfaces.Mediator;
using System;
using System.IO;
using System.Threading;
using System.Windows.Media.Imaging;
using System.Windows.Media;

namespace DaleGhent.NINA.GroundStation.Images
{
    public class ImageEventHandler(IProfileService profileService, IImageSaveMediator imageSaveMediator, IImageDataFactory imageDataFactory)
    {
        private readonly IProfileService profileService = profileService;
        private readonly IImageSaveMediator imageSaveMediator = imageSaveMediator;
        private readonly IImageDataFactory imageDataFactory = imageDataFactory;

        // 0 = idle, 1 = processing. Used to drop incoming events while one is already
        // in flight rather than queuing them. Queuing with a semaphore would keep every
        // ImageSavedEventArgs (each holding a ~80 MB BitmapSource Mat) alive simultaneously.
        private int _processing = 0;

        public void Start()
        {
            Stop();
            imageSaveMediator.ImageSaved += ImageSaveMeditator_ImageSaved;
        }

        public void Stop()
        {
            imageSaveMediator.ImageSaved -= ImageSaveMeditator_ImageSaved;
            ImageService.Instance.Image.Bitmap.Dispose();
        }

        private async void ImageSaveMeditator_ImageSaved(object sender, ImageSavedEventArgs msg)
        {
            // Drop this event if we are already processing one. For an image service the
            // latest available image is what matters; accumulating queued full-res Mats
            // would exhaust memory on constrained hardware (e.g. RPi).
            if (Interlocked.CompareExchange(ref _processing, 1, 0) != 0)
            {
                return;
            }

            // Extract everything we need from msg *before* the first await so that the
            // event args object (and its BitmapSource / Mat) can be GC'd immediately.
            // We re-read the image from disk ourselves so we never use msg.Image.
            var localPath = msg.PathToImage.LocalPath;
            var metaData = msg.MetaData;
            var stats = msg.Statistics;
            var starAnalysis = msg.StarDetectionAnalysis;
            var isBayered = msg.MetaData.Camera.SensorType > SensorType.Monochrome;
            var bitDepth = (int)profileService.ActiveProfile.CameraSettings.BitDepth;
            var rawConverter = profileService.ActiveProfile.CameraSettings.RawConverter;
            var stretchFactor = profileService.ActiveProfile.ImageSettings.AutoStretchFactor;
            var blackClipping = profileService.ActiveProfile.ImageSettings.BlackClipping;
            var unlinkedStretch = profileService.ActiveProfile.ImageSettings.UnlinkedStretch;
            var bayerPattern = msg.MetaData.Camera.SensorType;

            IRenderedImage renderedImage = null;
            BitmapSource scaledBitmap = null;
            BitmapFrame bitmapFrame = null;
            MemoryStream memoryStream = new MemoryStream();

            try
            {
                var imageData = await imageDataFactory.CreateFromFile(localPath, bitDepth, isBayered, rawConverter);
                renderedImage = imageData.RenderImage();

                if (isBayered && profileService.ActiveProfile.ImageSettings.DebayerImage)
                {
                    renderedImage = renderedImage.Debayer(saveColorChannels: unlinkedStretch, bayerPattern: bayerPattern);
                }

                renderedImage = await renderedImage.Stretch(stretchFactor, blackClipping, unlinkedStretch);

                if (GroundStation.GroundStationConfig.ImageServiceImageScaling < 100)
                {
                    var scaling = GroundStation.GroundStationConfig.ImageServiceImageScaling / 100d;
                    var transform = new ScaleTransform(scaling, scaling);
                    scaledBitmap = new TransformedBitmap(renderedImage.Image, transform);
                    bitmapFrame = BitmapFrame.Create(scaledBitmap);
                }
                else
                {
                    bitmapFrame = BitmapFrame.Create(renderedImage.Image);
                }

                string contentType = string.Empty;
                string fileExtension = string.Empty;

                switch ((ImageFormatEnum)GroundStation.GroundStationConfig.ImageServiceFormat)
                {
                    case ImageFormatEnum.JPEG:
                        var jpegBitmap = new JpegBitmapEncoder()
                        {
                            QualityLevel = GroundStation.GroundStationConfig.ImageServiceJpegQuality,
                        };
                        jpegBitmap.Frames.Add(bitmapFrame);
                        jpegBitmap.Save(memoryStream);
                        contentType = "image/jpeg";
                        fileExtension = "jpg";
                        break;

                    case ImageFormatEnum.PNG:
                        var pngBitmap = new PngBitmapEncoder();
                        pngBitmap.Frames.Add(bitmapFrame);
                        pngBitmap.Save(memoryStream);
                        contentType = "image/png";
                        fileExtension = "png";
                        break;
                }

                var capturedStream = memoryStream;
                memoryStream = null; // transfer ownership to ImageData

                ImageService.Instance.Image = new ImageData()
                {
                    Bitmap = capturedStream,
                    ImageMetaData = metaData,
                    ImageMimeType = contentType,
                    ImageFileExtension = fileExtension,
                    ImageStatistics = stats,
                    StarDetectionAnalysis = starAnalysis,
                    ImagePath = localPath,
                };
            }
            catch (Exception ex)
            {
                Logger.Error($"Exception: {ex.Message} {ex.StackTrace}");
            }
            finally
            {
                // Explicitly free all native OpenCV Mats.
                // BitmapFrame / TransformedBitmap / BitmapSource all wrap unmanaged Mats.
                bitmapFrame?.Dispose();
                scaledBitmap?.Dispose();
                (renderedImage?.Image as IDisposable)?.Dispose();
                memoryStream?.Dispose();
                Interlocked.Exchange(ref _processing, 0);
            }
        }
    }
}