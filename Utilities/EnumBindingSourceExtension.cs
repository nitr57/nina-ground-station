#region "copyright"

/*
    Copyright (c) 2024 Dale Ghent <daleg@elemental.org>

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/
*/

#endregion "copyright"

using System;
using System.ComponentModel;
using System.Reflection;

namespace DaleGhent.NINA.GroundStation.Utilities {
    public class EnumDescriptionTypeConverter(Type type) : EnumConverter(type) {
        public override object ConvertTo(ITypeDescriptorContext context, System.Globalization.CultureInfo culture, object value, Type destinationType) {
            if (destinationType == typeof(string)) {
                FieldInfo fi = value?.GetType().GetField(value.ToString());
                if (fi != null) {
                    var attributes = (DescriptionAttribute[])fi.GetCustomAttributes(typeof(DescriptionAttribute), false);
                    return ((attributes.Length > 0) && (!string.IsNullOrEmpty(attributes[0].Description))) ? attributes[0].Description : value.ToString();
                }

                return string.Empty;
            }

            return base.ConvertTo(context, culture, value, destinationType);
        }
    }
}
