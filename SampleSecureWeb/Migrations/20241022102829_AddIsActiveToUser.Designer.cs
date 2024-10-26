﻿// <auto-generated />
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using SampleSecureWeb.Data;

#nullable disable

namespace SampleSecureWeb.Migrations
{
    [DbContext(typeof(ApplicationDbContext))]
    [Migration("20241022102829_AddIsActiveToUser")]
    partial class AddIsActiveToUser
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "8.0.8");

            modelBuilder.Entity("SampleSecureWeb.Models.Student", b =>
                {
                    b.Property<string>("Nim")
                        .HasColumnType("TEXT");

                    b.Property<string>("FullName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Nim");

                    b.ToTable("Students");
                });

            modelBuilder.Entity("SampleSecureWeb.Models.User", b =>
                {
                    b.Property<string>("Username")
                        .HasColumnType("TEXT");

                    b.Property<string>("Email")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<bool>("IsActive")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Password")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("RoleName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Username");

                    b.ToTable("Users");
                });
#pragma warning restore 612, 618
        }
    }
}
